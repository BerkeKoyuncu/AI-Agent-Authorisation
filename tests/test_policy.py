from dataclasses import replace

import pytest

from agent_authz.models import (
    Action, AgentIdentity, ExecutionContext, Permission, TaskDelegation, ToolRequest, User,
)
from agent_authz.policy import authorise


@pytest.fixture
def records():
    meeting = Permission(Action.READ, "meeting_notes.txt")
    salary = Permission(Action.READ, "salary_data.txt")
    user = User("u1", frozenset({meeting, salary}))
    agent = AgentIdentity("a1", frozenset({meeting, salary}))
    task = TaskDelegation("t1", "u1", "a1", frozenset({meeting}))
    return {
        "users": {"u1": user}, "agents": {"a1": agent}, "tasks": {"t1": task},
    }


CONTEXT = ExecutionContext("u1", "a1", "t1")
REQUEST = ToolRequest(Action.READ, "meeting_notes.txt")


def test_allowed_action(records):
    assert authorise(CONTEXT, REQUEST, **records).allowed


def test_outside_task_scope(records):
    result = authorise(CONTEXT, ToolRequest(Action.READ, "salary_data.txt"), **records)
    assert (result.allowed, result.reason) == (False, "OUTSIDE_TASK_SCOPE")


@pytest.mark.parametrize(("field", "value", "reason"), [
    ("user_id", "unknown", "UNKNOWN_USER"),
    ("agent_id", "unknown", "UNKNOWN_AGENT"),
    ("task_id", "unknown", "INVALID_OR_INACTIVE_TASK"),
])
def test_unknown_identity_or_task(records, field, value, reason):
    result = authorise(replace(CONTEXT, **{field: value}), REQUEST, **records)
    assert (result.allowed, result.reason) == (False, reason)


def test_inactive_task(records):
    records["tasks"]["t1"] = replace(records["tasks"]["t1"], active=False)
    result = authorise(CONTEXT, REQUEST, **records)
    assert (result.allowed, result.reason) == (False, "INVALID_OR_INACTIVE_TASK")


def test_task_identity_mismatch(records):
    records["tasks"]["t1"] = replace(records["tasks"]["t1"], agent_id="a2")
    result = authorise(CONTEXT, REQUEST, **records)
    assert (result.allowed, result.reason) == (False, "TASK_IDENTITY_MISMATCH")


@pytest.mark.parametrize(("store", "key", "reason"), [
    ("users", "u1", "USER_PERMISSION_DENIED"),
    ("agents", "a1", "AGENT_PERMISSION_DENIED"),
])
def test_each_permission_layer_required(records, store, key, reason):
    records[store][key] = replace(records[store][key], permissions=frozenset())
    result = authorise(CONTEXT, REQUEST, **records)
    assert (result.allowed, result.reason) == (False, reason)


def test_action_is_part_of_permission(records):
    create = Permission(Action.CREATE, "meeting_notes.txt")
    for store, key in [("users", "u1"), ("agents", "a1")]:
        record = records[store][key]
        records[store][key] = replace(record, permissions=record.permissions | {create})
    result = authorise(CONTEXT, ToolRequest(Action.CREATE, "meeting_notes.txt"), **records)
    assert (result.allowed, result.reason) == (False, "OUTSIDE_TASK_SCOPE")


def test_invalid_request(records):
    result = authorise(CONTEXT, ToolRequest(Action.READ, ""), **records)
    assert (result.allowed, result.reason) == (False, "INVALID_REQUEST")
