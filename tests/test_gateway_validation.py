from dataclasses import FrozenInstanceError

import pytest

from agent_authz.gateway import tool_schemas
from agent_authz.gateway.models import Reason
from agent_authz.gateway.registry import TOOL_REGISTRY, ValidationError, canonicalise
from agent_authz.sandbox.environment import (
    MAX_BODY_LENGTH, MAX_DOCUMENT_LENGTH, MAX_QUERY_LENGTH, MAX_SUBJECT_LENGTH,
)


TOOLS = (
    ("read_document", "read", "document", {"resource_id": "meeting_notes.txt"}),
    ("search_documents", "search", "document", {"resource_id": "meeting_notes.txt", "query": "agenda"}),
    ("create_document", "create", "document", {"resource_id": "summary.txt", "content": ""}),
    ("edit_document", "edit", "document", {"resource_id": "summary.txt", "content": "Replacement"}),
    ("delete_document", "delete", "document", {"resource_id": "summary.txt"}),
    ("read_email", "read", "inbox", {"resource_id": "email_inbox"}),
    ("send_simulated_email", "send", "outbox", {
        "resource_id": "email_outbox", "destination": "review@example.invalid", "subject": "", "body": "",
    }),
)


@pytest.mark.parametrize(("name", "action", "kind", "arguments"), TOOLS)
def test_registry_mapping_schema_and_canonical_call(name, action, kind, arguments):
    assert set(TOOL_REGISTRY) == {row[0] for row in TOOLS}
    spec = TOOL_REGISTRY[name]
    assert (spec.action, spec.kind, spec.handler.__name__) == (action, kind, name)
    invocation = canonicalise({"tool": name, "arguments": arguments})
    assert (invocation.tool, invocation.action, invocation.resource_id) == (name, action, arguments["resource_id"])
    assert dict(invocation.arguments) == arguments
    schema = next(item for item in tool_schemas() if item["name"] == name)
    assert set(schema["parameters"]["required"]) == set(arguments)
    assert schema["parameters"]["additionalProperties"] is False


def test_registry_is_fixed_and_returned_schemas_and_invocations_are_detached():
    with pytest.raises(TypeError):
        TOOL_REGISTRY["other"] = TOOL_REGISTRY["read_document"]
    first = tool_schemas()
    pristine = tool_schemas()
    first[0]["parameters"]["properties"].clear()
    assert tool_schemas() == pristine

    arguments = {"resource_id": "summary.txt", "content": "Original"}
    raw = {"tool": "create_document", "arguments": arguments}
    invocation = canonicalise(raw)
    arguments.update(resource_id="meeting_notes.txt", content="Modified")
    raw["tool"] = "edit_document"
    assert invocation.tool == "create_document" and dict(invocation.arguments)["content"] == "Original"
    with pytest.raises(FrozenInstanceError):
        invocation.resource_id = "meeting_notes.txt"


@pytest.mark.parametrize("field", [
    "human_id", "user_id", "agent_id", "session_id", "session_token", "task_id", "delegation_id",
    "run_id", "permissions", "policy_mode", "action",
])
def test_authority_fields_are_rejected_at_both_levels(field):
    arguments = {"resource_id": "meeting_notes.txt"}
    raw = {"tool": "read_document", "arguments": arguments}
    with pytest.raises(ValidationError) as outer:
        canonicalise({**raw, field: "synthetic-override"})
    assert outer.value.reason is Reason.INVALID_ENVELOPE
    with pytest.raises(ValidationError) as inner:
        canonicalise({**raw, "arguments": {**arguments, field: "synthetic-override"}})
    assert inner.value.reason is Reason.INVALID_ARGUMENT


@pytest.mark.parametrize(("raw", "reason"), [
    (None, Reason.INVALID_ENVELOPE), (["read_document"], Reason.INVALID_ENVELOPE),
    ({"tool": "read_document"}, Reason.INVALID_ENVELOPE), ({"tool": 2, "arguments": {}}, Reason.INVALID_ENVELOPE),
    ({"tool": "extend_delegation", "arguments": {}}, Reason.UNKNOWN_TOOL),
    ({"tool": "read_document", "arguments": []}, Reason.INVALID_ARGUMENT),
    ({"tool": "read_document", "arguments": {}}, Reason.INVALID_ARGUMENT),
    ({"tool": "read_document", "arguments": {"resource_id": []}}, Reason.INVALID_ARGUMENT),
    ({"tool": "read_document", "arguments": {"resource_id": "email_inbox"}}, Reason.UNSUPPORTED_RESOURCE),
    ({"tool": "read_document", "arguments": {"resource_id": "./meeting_notes.txt"}}, Reason.UNSUPPORTED_RESOURCE),
    ({"tool": "read_document", "arguments": {"resource_id": " meeting_notes.txt"}}, Reason.UNSUPPORTED_RESOURCE),
    ({"tool": "search_documents", "arguments": {"resource_id": "meeting_notes.txt", "query": ""}},
     Reason.INVALID_ARGUMENT),
    ({"tool": "send_simulated_email", "arguments": {
        "resource_id": "email_outbox", "destination": "TEAM@example.invalid", "subject": "", "body": "",
    }}, Reason.UNREGISTERED_DESTINATION),
])
def test_structural_rejections(raw, reason):
    with pytest.raises(ValidationError) as error:
        canonicalise(raw)
    assert error.value.reason is reason


@pytest.mark.parametrize(("tool", "resource", "argument", "limit"), [
    ("search_documents", "meeting_notes.txt", "query", MAX_QUERY_LENGTH),
    ("create_document", "summary.txt", "content", MAX_DOCUMENT_LENGTH),
    ("edit_document", "summary.txt", "content", MAX_DOCUMENT_LENGTH),
    ("send_simulated_email", "email_outbox", "subject", MAX_SUBJECT_LENGTH),
    ("send_simulated_email", "email_outbox", "body", MAX_BODY_LENGTH),
])
def test_schema_limits_are_inclusive_and_use_sandbox_units(tool, resource, argument, limit):
    args = {"resource_id": resource}
    if tool == "send_simulated_email":
        args.update(destination="team@example.invalid", subject="", body="")
    args[argument] = "é" * limit
    raw = {"tool": tool, "arguments": args}
    assert dict(canonicalise(raw).arguments)[argument] == "é" * limit
    args[argument] += "é"
    with pytest.raises(ValidationError) as error:
        canonicalise(raw)
    assert error.value.reason is Reason.INVALID_ARGUMENT
