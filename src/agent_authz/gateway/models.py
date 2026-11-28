"""Canonical requests, policy decisions and gateway results."""

from dataclasses import dataclass
from enum import StrEnum

from ..models import Action
from ..sandbox.environment import OutboxMessage
from ..sandbox.fixtures import EmailDraft


class PolicyMode(StrEnum):
    A = "A"
    B = "B"
    C = "C"


POLICY_VERSION = "phase5-v1"


class Reason(StrEnum):
    ALLOWED = "ALLOWED"
    INVALID_ENVELOPE = "INVALID_ENVELOPE"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    UNSUPPORTED_RESOURCE = "UNSUPPORTED_RESOURCE"
    UNREGISTERED_DESTINATION = "UNREGISTERED_DESTINATION"
    INVALID_CONTEXT = "INVALID_CONTEXT"
    STATIC_GRANT_DENIED = "STATIC_GRANT_DENIED"
    TOOL_NOT_ALLOWLISTED = "TOOL_NOT_ALLOWLISTED"
    HUMAN_GRANT_DENIED = "HUMAN_GRANT_DENIED"
    AGENT_GRANT_DENIED = "AGENT_GRANT_DENIED"
    OUTSIDE_TASK_SCOPE = "OUTSIDE_TASK_SCOPE"
    DESTINATION_DENIED = "DESTINATION_DENIED"
    READ_REQUIRED = "READ_REQUIRED"
    TASK_GRANTS_CHANGED = "TASK_GRANTS_CHANGED"
    DELEGATION_EXPIRED = "DELEGATION_EXPIRED"
    DELEGATION_REVOKED = "DELEGATION_REVOKED"
    DELEGATION_INACTIVE = "DELEGATION_INACTIVE"
    STALE_RECORD = "STALE_RECORD"
    TASK_EFFECT_CONSUMED = "TASK_EFFECT_CONSUMED"
    MUTATION_UNCERTAIN = "MUTATION_UNCERTAIN"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    RUNTIME_UNAVAILABLE = "RUNTIME_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class Invocation:
    tool: str
    action: Action
    resource_id: str
    arguments: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class RecordVersions:
    human: int | None = None
    agent: int | None = None
    delegation: int | None = None


@dataclass(frozen=True, slots=True)
class Decision:
    mode: PolicyMode
    reason: Reason
    versions: RecordVersions = RecordVersions()
    policy_version: str = POLICY_VERSION

    @property
    def allowed(self) -> bool:
        return self.reason is Reason.ALLOWED


class Execution(StrEnum):
    NOT_DISPATCHED = "not_dispatched"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


ToolData = str | tuple[str, ...] | EmailDraft | OutboxMessage | None


@dataclass(frozen=True, slots=True)
class Timing:
    policy_ns: int | None
    enforcement_ns: int
    executor_ns: int | None
    gateway_overhead_ns: int
    audit_writes_ns: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class PreliminaryObservation:
    """A captured decision, or confirmed non-occurrence when decision is None."""

    decision: Decision | None


@dataclass(frozen=True, slots=True)
class GatewayResult:
    request_id: str
    decision: Decision
    execution: Execution
    data: ToolData
    execution_reason: str | None
    lifecycle: str | None
    failed_audit_events: tuple[str, ...]
    timing: Timing
    preliminary: PreliminaryObservation | None = None

    @property
    def dispatched(self) -> bool:
        return self.execution is not Execution.NOT_DISPATCHED

    def model_response(self) -> dict[str, object]:
        if not self.decision.allowed:
            return {"status": "denied"}
        if self.execution is not Execution.SUCCEEDED:
            return {"status": "error"}
        data: object = self.data
        if isinstance(self.data, EmailDraft):
            data = {"destination": self.data.destination, "subject": self.data.subject, "body": self.data.body}
        elif isinstance(self.data, OutboxMessage):
            data = {"message_id": self.data.message_id}
        return {"status": "ok", "data": data}
