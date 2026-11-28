import json
from dataclasses import replace

import pytest

from agent_authz.audit.completeness import Issue, Status, assess_journal
from agent_authz.audit.reader import Journal, ReadIssue, read_journal
from agent_authz.audit.schema import SchemaIssue
from agent_authz.gateway import PolicyMode
from agent_authz.scenarios.runner import run_scenario


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "source.jsonl"
    assessment = run_scenario("N1", PolicyMode.A, audit_path=path).audit
    assert assessment.globally_clean
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()], assessment.attempts[0].observation


def write_copy(tmp_path, records):
    copy = tmp_path / "copy.jsonl"
    copy.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return copy


@pytest.mark.parametrize(("change", "expected", "issue"), [
    ("missing", Status.INCOMPLETE, Issue.MISSING_EVENT),
    ("duplicate", Status.INCONSISTENT, Issue.DUPLICATE_EVENT),
    ("reordered", Status.INCONSISTENT, Issue.EVENT_ORDER),
    ("admission", Status.INCONSISTENT, Issue.DECISION_CONFLICT),
    ("conflicting_admissions", Status.INCONSISTENT, Issue.DECISION_CONFLICT),
    ("dispatch", Status.INCOMPLETE, Issue.MISSING_EVENT),
    ("target", Status.INCONSISTENT, Issue.OPERATION_CONFLICT),
    ("policy", Status.INCONSISTENT, Issue.POLICY_CONFLICT),
    ("policy_version", Status.INCONSISTENT, Issue.POLICY_CONFLICT),
    ("binding", Status.INCONSISTENT, Issue.BINDING_CONFLICT),
    ("version", Status.INCONSISTENT, Issue.VERSION_CONFLICT),
    ("execution", Status.INCONSISTENT, Issue.EXECUTION_CONFLICT),
    ("duration", Status.INCONSISTENT, Issue.TIMING_CONFLICT),
    ("write_history", Status.INCONSISTENT, Issue.TIMING_CONFLICT),
])
def test_local_audit_faults_keep_order_multiplicity_and_issue_codes(sample, tmp_path, change, expected, issue):
    rows, observation = sample
    if change == "missing":
        rows.pop()
    elif change == "duplicate":
        rows.append(rows[-1].copy())
    elif change == "reordered":
        rows[-1], rows[-2] = rows[-2], rows[-1]
    elif change == "admission":
        rows[4].update(allowed=False, reason="STATIC_GRANT_DENIED", dispatched=False, executor_ns=None)
    elif change == "conflicting_admissions":
        rows.insert(5, {**rows[4], "allowed": False, "reason": "STATIC_GRANT_DENIED",
                        "dispatched": False, "executor_ns": None})
    elif change == "dispatch":
        rows[5]["dispatched"] = False
    elif change == "target":
        rows[-1]["resource_id"] = "public_report.txt"
    elif change == "policy":
        rows[-1]["policy_mode"] = "B"
    elif change == "policy_version":
        rows[-1]["policy_version"] = "phase5-v2"
    elif change == "binding":
        rows[-1]["run_id"] = "different-synthetic-run"
    elif change == "version":
        rows[4]["human_version"] += 1
    elif change == "execution":
        rows[-1].update(execution="failed", reason="DOCUMENT_MISSING")
    elif change == "duration":
        rows[-1]["executor_ns"] += 1
    elif change == "write_history":
        rows[-1]["prior_audit_writes_ns"][-1][1] += 1
    summary = assess_journal(read_journal(write_copy(tmp_path, rows)), [observation])
    attempt, = summary.attempts
    assert attempt.status is expected and any(item.issue is issue for item in attempt.problems)
    assert summary.denominator == 1 and summary.numerator == 0 and not summary.globally_clean
    if change == "duplicate":
        assert list(row.event for row in attempt.records).count("outcome") == 2
    if change == "conflicting_admissions":
        assert list(row.event for row in attempt.records).count("admission") == 2
        assert Issue.DUPLICATE_EVENT.value in summary.issue_counts
    if change == "dispatch":
        assert summary.journal.problems[0].issue is SchemaIssue.INVALID_FIELD


def test_lifecycle_conflict_is_reported_separately(tmp_path):
    path = tmp_path / "send.jsonl"
    audit = run_scenario("N4", PolicyMode.C, audit_path=path).audit
    assert audit.globally_clean
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[-1]["status"] = "failure_no_effect"
    copy = read_journal(write_copy(tmp_path, rows))
    assessment = assess_journal(copy, [entry.observation for entry in audit.attempts])
    assert assessment.attempts[-1].status is Status.INCONSISTENT
    assert Issue.LIFECYCLE_CONFLICT.value in assessment.issue_counts


def test_orphans_truncation_and_zero_denominator(sample, tmp_path):
    rows, observation = sample
    path = write_copy(tmp_path, [*rows, {**rows[0], "request_id": "unknown-request"}])
    with path.open("ab") as output:
        output.write(b'{"event":')
    journal = read_journal(path)
    audit = assess_journal(journal, [observation])
    assert audit.numerator == audit.denominator == 1 and audit.fraction == 1
    assert audit.orphan_lines == (len(rows) + 1,) and audit.invalid_records == 1
    assert audit.issue_counts == {"truncated_line": 1, "orphan_event": 1}
    assert journal.problems[0].issue is ReadIssue.TRUNCATED_LINE
    assert not audit.globally_clean
    assert assess_journal(journal, []).fraction is None
    assert assess_journal(Journal((), ()), []).counts == dict.fromkeys(Status, 0)


def test_missing_correlation_is_counted_and_conflicting_inventory_is_not_double_counted(sample, tmp_path):
    rows, observation = sample
    journal = read_journal(write_copy(tmp_path, rows))
    missing = replace(observation, sequence=2, request_id=None, outcome=None)
    summary = assess_journal(journal, [observation, missing])
    assert summary.denominator == 2 and summary.numerator == 1
    assert summary.attempts[1].status is Status.INCOMPLETE
    assert Issue.MISSING_CORRELATION.value in summary.issue_counts
    duplicate = assess_journal(journal, [observation, observation])
    assert duplicate.denominator == 1 and duplicate.attempts[0].status is Status.INCONSISTENT
    same_request = assess_journal(journal, [observation, replace(observation, sequence=2)])
    assert same_request.denominator == 2 and same_request.numerator == 0
    assert len(same_request.uncorrelated_lines) == len(rows)


def test_interrupted_attempt_without_terminal_observation_stays_unknown(sample, tmp_path):
    rows, observation = sample
    journal = read_journal(write_copy(tmp_path, rows[:4]))
    result = assess_journal(journal, [replace(observation, outcome=None, effect=None)])
    assert result.attempts[0].status is Status.UNKNOWN
    assert result.attempts[0].records[-1].event == "dispatch_intent"
    assert result.attempts[0].observation.outcome is None


def test_wall_clock_order_does_not_override_line_order(sample, tmp_path):
    rows, observation = sample
    for index, row in enumerate(rows):
        row["timestamp"] = f"2026-01-01T00:00:{59-index:02d}+00:00"
    result = assess_journal(read_journal(write_copy(tmp_path, rows)), [observation])
    assert result.globally_clean
