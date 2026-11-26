import json

import pytest

from agent_authz.agent.models import AgentError, Issue, ToolProposal
from agent_authz.agent.parser import MAX_JSON_DEPTH, decode_json, parse_proposal


@pytest.mark.parametrize("arguments", [
    {"resource_id": "meeting_notes.txt", "extra": {"number": 1, "flag": False, "array": [None]}},
    '{"resource_id":"meeting_notes.txt","extra":{"number":1,"flag":false,"array":[null]}}',
])
def test_decoded_and_json_arguments_preserve_values_and_unexpected_fields(arguments):
    envelope = {"tool": "read_document", "arguments": arguments, "policy_mode": "A"}
    proposal = parse_proposal(ToolProposal(envelope, "call-1"), 9, 1000)
    assert proposal.issue is None and proposal.call.sequence == 9 and proposal.provider_id == "call-1"
    assert json.loads(proposal.request_json) == {
        "tool": "read_document", "policy_mode": "A",
        "arguments": {"resource_id": "meeting_notes.txt", "extra": {"number": 1, "flag": False, "array": [None]}},
    }
    envelope["tool"] = "replacement"
    if type(arguments) is dict:
        arguments["resource_id"] = "replacement"
    assert json.loads(proposal.request_json)["arguments"]["resource_id"] == "meeting_notes.txt"
    assert proposal.call.tool == "read_document"


@pytest.mark.parametrize(("arguments", "issue"), [
    ("{", Issue.INVALID_JSON),
    ('{"resource_id":"a","resource_id":"b"}', Issue.DUPLICATE_KEY),
    ('{"nested":{"value":1,"value":2}}', Issue.DUPLICATE_KEY),
    ('{"value":NaN}', Issue.INVALID_JSON),
    ('{"value":Infinity}', Issue.INVALID_JSON),
    ('{"value":-Infinity}', Issue.INVALID_JSON),
    ('{"value":1e9999}', Issue.INVALID_JSON),
    ('{"x":' + '[' * MAX_JSON_DEPTH + '0' + ']' * MAX_JSON_DEPTH + '}', Issue.STRUCTURE_LIMIT),
    ("[]", Issue.MALFORMED_PROPOSAL), ([], Issue.MALFORMED_PROPOSAL),
    ("1", Issue.MALFORMED_PROPOSAL), (False, Issue.MALFORMED_PROPOSAL), (None, Issue.MALFORMED_PROPOSAL),
])
def test_rejected_arguments_have_no_normalised_gateway_payload(arguments, issue):
    proposal = parse_proposal(ToolProposal({"tool": "read_document", "arguments": arguments}), 1, 1000)
    assert proposal.issue is issue and proposal.request_json is None
    assert proposal.call.tool == "invalid_tool_call"


@pytest.mark.parametrize(("identifier", "index"), [(True, None), ("bad\nidentifier", None), ("x" * 129, None),
                                                      (None, -1), (None, "0"), (None, True)])
def test_invalid_provider_correlation_is_rejected_without_discarding_the_tool_observation(identifier, index):
    proposal = parse_proposal(ToolProposal({"tool": "read_document", "arguments": {}}, identifier, index), 4, 1000)
    assert proposal.call.sequence == 4 and proposal.raw_json and proposal.request_json is None
    assert proposal.issue is Issue.INVALID_CORRELATION


def test_decoded_values_do_not_get_repaired_or_coerced():
    payload = {"tool": "send_simulated_email", "arguments": {"resource_id": 10, "destination": "invalid"}}
    proposal = parse_proposal(ToolProposal(payload), 1, 1000)
    assert json.loads(proposal.request_json) == payload


def test_limits_use_utf8_bytes_and_reject_before_decoding():
    with pytest.raises(AgentError) as error:
        decode_json('"é"', 3)
    assert error.value.issue is Issue.RESPONSE_TOO_LARGE
    with pytest.raises(AgentError) as error:
        decode_json(b"\xff", 10)
    assert error.value.issue is Issue.INVALID_JSON
    assert decode_json(b'{"quoted":"[\\\"]"}', 24) == {"quoted": '["]'}


def test_argument_payload_limit_rejects_without_discarding_bounded_raw_observation(monkeypatch):
    monkeypatch.setattr("agent_authz.agent.parser.MAX_ARGUMENT_BYTES", 32)
    arguments = '{"resource_id":"meeting_notes.txt"}'
    proposal = parse_proposal(ToolProposal({"tool": "read_document", "arguments": arguments}), 1, 1000)
    assert proposal.issue is Issue.RESPONSE_TOO_LARGE
    assert proposal.raw_json is not None and proposal.request_json is None
