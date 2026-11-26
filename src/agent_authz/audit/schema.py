"""Allowlisted schema for the local synthetic security journal."""

import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType

from ..gateway.models import Execution, PolicyMode, Reason
from ..gateway.registry import TOOL_REGISTRY
from ..identity.principals import PRINCIPAL_FIXTURES, PrincipalKind
from ..models import Action
from ..sandbox.catalogue import RESOURCE_CATALOGUE
from ..sandbox.environment import SIMULATOR_DESTINATIONS
from ..sandbox.errors import ErrorCode
from ..tasks import TASK_CATALOGUE
from . import AUDIT_SCHEMA_VERSION


EVENT_ORDER = ("attempt", "validation", "preliminary", "dispatch_intent", "admission", "dispatch", "outcome", "lifecycle")
BINDING_FIELDS = ("run_id", "session_id", "human_id", "agent_id")
TASK_FIELDS = ("task_id", "delegation_id")
OPERATION_FIELDS = ("tool", "action", "resource_id")
VERSION_FIELDS = ("human_version", "agent_version", "delegation_version")
_DECISION_FIELDS = {"allowed", "reason", *VERSION_FIELDS}
_COMMON_FIELDS = {
    "schema_version", "event", "request_id", "timestamp", "policy_mode", "policy_version",
    "policy_ns", "enforcement_ns", "executor_ns", "prior_audit_writes_ns",
}
_OPTIONAL_FIELDS = {*BINDING_FIELDS, *TASK_FIELDS, *OPERATION_FIELDS, "destination"}
_EVENT_FIELDS = {
    "attempt": set(),
    "validation": {"valid", "reason"},
    "preliminary": _DECISION_FIELDS,
    "dispatch_intent": {*_DECISION_FIELDS, "provisional"},
    "admission": _DECISION_FIELDS,
    "dispatch": {"dispatched"},
    "outcome": {"execution", "reason"},
    "lifecycle": {"status", "reserved_send"},
}
_VALIDATION_REASONS = {
    Reason.INVALID_ENVELOPE, Reason.UNKNOWN_TOOL, Reason.INVALID_ARGUMENT,
    Reason.UNSUPPORTED_RESOURCE, Reason.UNREGISTERED_DESTINATION, Reason.RUNTIME_UNAVAILABLE,
}
_OUTCOME_REASONS = {code.name for code in ErrorCode}
LIFECYCLE_EXECUTION = MappingProxyType({
    "completed": Execution.SUCCEEDED,
    "expired_after_effect": Execution.SUCCEEDED,
    "revoked_after_effect": Execution.SUCCEEDED,
    "completion_unavailable": Execution.SUCCEEDED,
    "failure_no_effect": Execution.FAILED,
    "quarantined": Execution.UNKNOWN,
})
_DECISION_REASONS = frozenset(Reason)
_PRINCIPAL_IDS = {
    kind: {record.principal_id for record in PRINCIPAL_FIXTURES if record.kind is kind}
    for kind in PrincipalKind
}
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}")
_REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,128}(?:\.[1-9][0-9]{0,18})?")
_POLICY_VERSION = re.compile(r"phase[1-9][0-9]{0,2}-v[1-9][0-9]{0,5}")
_UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", re.ASCII)


class SchemaIssue(StrEnum):
    LEGACY_UNVERSIONED = "legacy_unversioned"
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"
    UNKNOWN_EVENT = "unknown_event"
    UNEXPECTED_FIELD = "unexpected_field"
    MISSING_FIELD = "missing_field"
    INVALID_FIELD = "invalid_field"
    INVALID_TIMING = "invalid_timing"


class AuditSchemaError(ValueError):
    def __init__(self, issue: SchemaIssue) -> None:
        self.issue = issue
        super().__init__(issue.value)


def is_duration(value: object) -> bool:
    return type(value) is int and 0 <= value < 2**63


def _require(condition: bool, issue: SchemaIssue = SchemaIssue.INVALID_FIELD) -> None:
    if not condition:
        raise AuditSchemaError(issue)


def _group(record: Mapping[str, object], fields: tuple[str, ...]) -> bool:
    present = set(fields) & record.keys()
    _require(not present or len(present) == len(fields), SchemaIssue.MISSING_FIELD)
    return bool(present)


def _metadata(record: Mapping[str, object]) -> tuple[bool, bool]:
    binding = _group(record, BINDING_FIELDS)
    scoped = _group(record, TASK_FIELDS)
    operation = _group(record, OPERATION_FIELDS)
    if binding:
        for field in ("run_id", "session_id"):
            value = record[field]
            _require(isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None)
        for field, kind in (("human_id", PrincipalKind.HUMAN), ("agent_id", PrincipalKind.AGENT)):
            value = record[field]
            _require(isinstance(value, str) and value in _PRINCIPAL_IDS[kind])
    if scoped:
        delegation = record["delegation_id"]
        task_id = record["task_id"]
        _require(binding and operation and record["policy_mode"] == PolicyMode.C)
        _require(isinstance(delegation, str) and _IDENTIFIER.fullmatch(delegation) is not None)
        _require(isinstance(task_id, str) and task_id in TASK_CATALOGUE)
        task = TASK_CATALOGUE[task_id]
        _require((task.human_id, task.agent_id) == (record["human_id"], record["agent_id"]))
    if operation:
        tool, action, resource_id = (record[field] for field in OPERATION_FIELDS)
        _require(all(isinstance(value, str) for value in (tool, action, resource_id)))
        _require(tool in TOOL_REGISTRY and resource_id in RESOURCE_CATALOGUE)
        spec = TOOL_REGISTRY[tool]
        _require(action == spec.action and RESOURCE_CATALOGUE[resource_id].kind is spec.kind)
        if spec.action is Action.SEND:
            route = record.get("destination")
            _require(isinstance(route, str) and route in SIMULATOR_DESTINATIONS)
        else:
            _require("destination" not in record, SchemaIssue.UNEXPECTED_FIELD)
    else:
        _require("destination" not in record, SchemaIssue.UNEXPECTED_FIELD)
    return binding, operation


def _timing(record: Mapping[str, object], event: str) -> tuple[tuple[str, int], ...]:
    policy, enforcement, executor = (record[key] for key in ("policy_ns", "enforcement_ns", "executor_ns"))
    _require(is_duration(policy), SchemaIssue.INVALID_TIMING)
    terminal = EVENT_ORDER.index(event) >= EVENT_ORDER.index("admission")
    dispatched = terminal and (event != "admission" or record["allowed"] is True)
    enforcement_ok = is_duration(enforcement) and enforcement >= policy if terminal else enforcement is None
    _require(enforcement_ok, SchemaIssue.INVALID_TIMING)
    _require(is_duration(executor) if dispatched else executor is None, SchemaIssue.INVALID_TIMING)
    history = record["prior_audit_writes_ns"]
    _require(type(history) in (list, tuple) and len(history) < len(EVENT_ORDER), SchemaIssue.INVALID_TIMING)
    result = []
    for entry in history:
        _require(type(entry) in (list, tuple) and len(entry) == 2, SchemaIssue.INVALID_TIMING)
        name, duration = entry
        _require(isinstance(name, str) and name in EVENT_ORDER and is_duration(duration), SchemaIssue.INVALID_TIMING)
        result.append((name, duration))
    return tuple(result)


def _stage(record: Mapping[str, object], event: str, binding: bool, operation: bool) -> None:
    if event == "validation":
        valid, reason = record["valid"], record["reason"]
        _require(type(valid) is bool and valid == operation)
        _require(reason is None if valid else isinstance(reason, str) and reason in _VALIDATION_REASONS)
    elif event in {"preliminary", "dispatch_intent", "admission"}:
        allowed, reason = record["allowed"], record["reason"]
        _require(type(allowed) is bool and isinstance(reason, str) and reason in _DECISION_REASONS)
        _require(allowed == (reason == Reason.ALLOWED))
        _require(not allowed or (binding and operation))
        _require(event == "admission" or operation)
        if event == "dispatch_intent":
            _require(allowed and record["provisional"] is True)
        if event == "admission":
            _require("dispatched" not in record if allowed else record.get("dispatched") is False)
        for field in VERSION_FIELDS:
            value = record[field]
            _require(value is None or (is_duration(value) and value > 0))
        if allowed:
            _require(record["human_version"] is not None and record["agent_version"] is not None)
            if record["policy_mode"] == PolicyMode.C:
                _require(record["delegation_version"] is not None)
        if record["delegation_version"] is not None:
            _require("delegation_id" in record)
    elif event in {"dispatch", "outcome", "lifecycle"}:
        _require(binding and operation)
        if event == "dispatch":
            _require(record["dispatched"] is True)
        elif event == "outcome":
            execution, reason = record["execution"], record["reason"]
            _require(isinstance(execution, str) and execution in (Execution.SUCCEEDED, Execution.FAILED, Execution.UNKNOWN))
            if execution == Execution.FAILED:
                _require(isinstance(reason, str) and reason in _OUTCOME_REASONS)
            else:
                _require(reason is None if execution == Execution.SUCCEEDED else reason == "EXECUTOR_ERROR")
        else:
            status, reserved = record["status"], record["reserved_send"]
            _require(isinstance(status, str) and status in LIFECYCLE_EXECUTION and type(reserved) is bool)
            _require(record["action"] in (Action.CREATE, Action.EDIT, Action.DELETE, Action.SEND))
            if status != "quarantined":
                _require("delegation_id" in record)
            _require(reserved == (record["action"] == Action.SEND and "delegation_id" in record))


def validate_event(record: object) -> Mapping[str, object]:
    """Return an immutable validated event. Error messages contain only issue codes."""
    _require(type(record) is dict)
    _require("schema_version" in record, SchemaIssue.LEGACY_UNVERSIONED)
    version = record["schema_version"]
    _require(type(version) is int, SchemaIssue.INVALID_FIELD)
    _require(version == AUDIT_SCHEMA_VERSION, SchemaIssue.UNSUPPORTED_SCHEMA_VERSION)
    event = record.get("event")
    _require(isinstance(event, str) and event in _EVENT_FIELDS, SchemaIssue.UNKNOWN_EVENT)
    required = _COMMON_FIELDS | _EVENT_FIELDS[event]
    optional = _OPTIONAL_FIELDS | ({"dispatched"} if event == "admission" else set())
    _require(required <= record.keys(), SchemaIssue.MISSING_FIELD)
    _require(record.keys() <= required | optional, SchemaIssue.UNEXPECTED_FIELD)
    request_id, version, timestamp = (record[field] for field in ("request_id", "policy_version", "timestamp"))
    _require(isinstance(request_id, str) and _REQUEST_ID.fullmatch(request_id) is not None)
    _require(isinstance(version, str) and _POLICY_VERSION.fullmatch(version) is not None)
    _require(isinstance(record["policy_mode"], str) and record["policy_mode"] in tuple(PolicyMode))
    _require(isinstance(timestamp, str) and _UTC_TIMESTAMP.fullmatch(timestamp) is not None)
    try:
        timestamp_ok = datetime.fromisoformat(timestamp).utcoffset() == timedelta(0)
    except ValueError:
        timestamp_ok = False
    _require(timestamp_ok)
    binding, operation = _metadata(record)
    _stage(record, event, binding, operation)
    return MappingProxyType({**record, "prior_audit_writes_ns": _timing(record, event)})
