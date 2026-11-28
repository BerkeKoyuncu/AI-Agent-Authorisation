import json
from dataclasses import asdict

import pytest

from agent_authz.agent.models import Method, RunLimits, Termination
from agent_authz.audit.completeness import Issue, Status
from agent_authz.audit.reader import read_journal
from agent_authz.gateway import Gateway, PolicyMode
from agent_authz.scenarios.authority import Evidence
from agent_authz.scenarios.runner import run_scenario


@pytest.mark.parametrize("case_id", tuple(f"N{n}" for n in range(1, 7)))
@pytest.mark.parametrize("mode", tuple(PolicyMode))
@pytest.mark.parametrize("method", (Method.REPLAY, Method.STUB))
def test_persisted_normal_scenario_audit_matrix(tmp_path, case_id, mode, method):
    path = tmp_path / "journal.jsonl"
    result = run_scenario(case_id, mode, method, audit_path=path)
    audit = result.audit
    assert audit is not None and audit.globally_clean
    assert audit.journal == read_journal(path)
    assert audit.numerator == audit.denominator == len(result.attempts)
    assert result.tool_sequence is Evidence.SUCCESS
    for attempt, assessment in zip(result.attempts, audit.attempts, strict=True):
        assert assessment.status is Status.COMPLETE
        assert assessment.observation.sequence == attempt.sequence
        assert assessment.observation.request_id == attempt.request_id
        assert assessment.observation.run_id == result.run.run_id
        assert assessment.observation.effect is Evidence.SUCCESS
        assert assessment.observation.outcome.decision.allowed
        assert assessment.observation.outcome.preliminary.decision.allowed and attempt.preliminary_allowed is True
        assert [row.event for row in assessment.records] == list(assessment.required_events)
        assert len(assessment.observation.outcome.timing.audit_writes_ns) == len(assessment.records)
    expected_lifecycle = mode is PolicyMode.C and case_id in {"N3", "N4", "N5"}
    assert any(row.event == "lifecycle" for row in audit.journal.records) is expected_lifecycle


def test_persistence_is_explicit_and_requires_fresh_path(tmp_path):
    assert run_scenario("N1", PolicyMode.C).audit is None
    path = tmp_path / "journal.jsonl"
    run_scenario("N1", PolicyMode.C, audit_path=path)
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        run_scenario("N1", PolicyMode.C, audit_path=path)
    assert path.read_bytes() == original


def test_unprocessed_proposal_does_not_enter_audit_denominator(tmp_path):
    normal = run_scenario("N1", PolicyMode.C)
    prefix = [asdict(message) for message in normal.run.conversation[:2]]
    size = len(json.dumps(prefix, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    result = run_scenario("N1", PolicyMode.C, limits=RunLimits(max_conversation_bytes=size),
                          audit_path=tmp_path / "bounded.jsonl")
    assert result.run.termination is Termination.CONVERSATION_LIMIT
    assert len(result.attempts) == 1 and result.attempts[0].request_id is None
    assert result.audit.denominator == 0 and result.audit.fraction is None
    assert not result.audit.journal.records


def test_gateway_exception_preserves_independent_inventory_without_request_id(tmp_path, monkeypatch):
    def unavailable(*args):
        raise RuntimeError("private synthetic exception marker")

    monkeypatch.setattr(Gateway, "handle", unavailable)
    result = run_scenario("N1", PolicyMode.C, audit_path=tmp_path / "error.jsonl")
    assert result.run.termination is Termination.GATEWAY_ERROR
    assert result.audit.denominator == 1 and result.audit.numerator == 0
    attempt, = result.audit.attempts
    assert attempt.status is Status.INCOMPLETE
    assert attempt.observation.request_id is None and attempt.observation.outcome is None
    assert any(problem.issue is Issue.MISSING_CORRELATION for problem in attempt.problems)
