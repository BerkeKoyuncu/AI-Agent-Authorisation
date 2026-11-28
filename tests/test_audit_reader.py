import json

import pytest

from agent_authz.audit.reader import ReadIssue, read_journal
from agent_authz.audit.schema import AuditSchemaError, SchemaIssue
from agent_authz.gateway import PolicyMode
from agent_authz.gateway.audit import JsonlAudit
from agent_authz.scenarios.runner import run_scenario


@pytest.fixture
def entry(tmp_path):
    path = tmp_path / "source.jsonl"
    run_scenario("N1", PolicyMode.C, audit_path=path)
    return path.read_bytes().splitlines()[0] + b"\n"


@pytest.mark.parametrize(("malformed", "issue"), [
    (b'{"other":\xff}\n', ReadIssue.INVALID_UTF8),
    (b'{"incomplete":\n', ReadIssue.MALFORMED_JSON),
    (b'{"outer":{"repeat":1,"repeat":2}}\n', ReadIssue.DUPLICATE_KEY),
    (b'{"duration":NaN}\n', ReadIssue.NONFINITE_NUMBER),
    (b'{"duration":Infinity}\n', ReadIssue.NONFINITE_NUMBER),
    (b'{"duration":1e400}\n', ReadIssue.NONFINITE_NUMBER),
    (b'["synthetic"]\n', ReadIssue.NON_OBJECT),
])
def test_bad_line_does_not_hide_other_valid_records(entry, tmp_path, malformed, issue):
    path = tmp_path / "copy.jsonl"
    raw = entry + malformed + entry
    path.write_bytes(raw)
    result = read_journal(path)
    assert [record.line for record in result.records] == [1, 3]
    problem, = result.problems
    assert (problem.line, problem.issue) == (2, issue)
    assert result.invalid_records == 1 and path.read_bytes() == raw


@pytest.mark.parametrize(("field", "value", "issue"), [
    ("schema_version", None, SchemaIssue.LEGACY_UNVERSIONED),
    ("schema_version", 9, SchemaIssue.UNSUPPORTED_SCHEMA_VERSION),
    ("schema_version", True, SchemaIssue.INVALID_FIELD),
    ("request_id", None, SchemaIssue.MISSING_FIELD),
    ("event", "unknown-event", SchemaIssue.UNKNOWN_EVENT),
    ("raw_prompt", "private sentinel", SchemaIssue.UNEXPECTED_FIELD),
    ("timestamp", "2026-01-01T10:00:00+01:00", SchemaIssue.INVALID_FIELD),
    ("policy_mode", ["A"], SchemaIssue.INVALID_FIELD),
    ("agent_id", "unregistered", SchemaIssue.INVALID_FIELD),
    ("resource_id", "unregistered", SchemaIssue.INVALID_FIELD),
    ("target", "unchecked-data", SchemaIssue.UNEXPECTED_FIELD),
    ("policy_ns", -1, SchemaIssue.INVALID_TIMING),
    ("policy_ns", True, SchemaIssue.INVALID_TIMING),
    ("policy_ns", 1.25, SchemaIssue.INVALID_TIMING),
    ("executor_ns", 0, SchemaIssue.INVALID_TIMING),
    ("prior_audit_writes_ns", [["validation", False]], SchemaIssue.INVALID_TIMING),
])
def test_schema_rejects_invalid_or_unchecked_fields_safely(entry, tmp_path, field, value, issue):
    record = json.loads(entry)
    if value is None:
        record.pop(field)
    else:
        record[field] = value
    path = tmp_path / "copy.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    result = read_journal(path)
    assert not result.records
    assert result.problems[0].issue is issue
    assert "private sentinel" not in repr(result.problems)

    not_created = tmp_path / "refused.jsonl"
    with pytest.raises(AuditSchemaError) as failure:
        JsonlAudit(not_created)(record)
    assert str(failure.value) == issue.value
    assert not not_created.exists()


def test_line_and_file_limits_and_truncated_final_record(entry, tmp_path):
    path = tmp_path / "bounds.jsonl"
    path.write_bytes(entry + b"x" * (4 * len(entry)) + b"\n" + entry + entry.rstrip(b"\n"))
    result = read_journal(path, max_line_bytes=len(entry))
    assert [row.line for row in result.records] == [1, 3]
    assert [(issue.line, issue.issue) for issue in result.problems] == [
        (2, ReadIssue.OVERSIZED_LINE), (4, ReadIssue.TRUNCATED_LINE),
    ]
    capped = read_journal(path, max_line_bytes=len(entry), max_file_bytes=len(entry))
    assert len(capped.records) == 1 and capped.problems[0].issue is ReadIssue.FILE_LIMIT
    assert capped.invalid_records == 0


def test_missing_file_unreadable_path_and_empty_journal(tmp_path):
    missing = read_journal(tmp_path / "absent.jsonl")
    assert missing.problems[0].issue is ReadIssue.MISSING_FILE
    unreadable = read_journal(tmp_path)
    assert unreadable.problems[0].issue is ReadIssue.UNREADABLE_FILE
    path = tmp_path / "empty.jsonl"
    path.touch()
    assert read_journal(path).problems == ()


def test_scoped_allow_requires_observed_security_record_versions(tmp_path):
    path = tmp_path / "source.jsonl"
    run_scenario("N1", PolicyMode.C, audit_path=path)
    preliminary = json.loads(path.read_text(encoding="utf-8").splitlines()[2])
    preliminary["delegation_version"] = None
    with pytest.raises(AuditSchemaError, match="^invalid_field$"):
        JsonlAudit(tmp_path / "refused.jsonl")(preliminary)
