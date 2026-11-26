"""Trusted attempt evidence independent of the persisted journal."""

from dataclasses import dataclass

from ..gateway.models import Decision, Execution, GatewayResult, Invocation, PolicyMode, RecordVersions, Timing
from ..models import Action


@dataclass(frozen=True, slots=True)
class BindingObservation:
    run_id: str
    session_id: str
    human_id: str
    agent_id: str
    task_id: str | None = None
    delegation_id: str | None = None


@dataclass(frozen=True, slots=True)
class OperationObservation:
    tool: str
    action: Action
    resource_id: str
    destination: str | None = None

    @classmethod
    def from_invocation(cls, invocation: Invocation) -> "OperationObservation":
        return cls(invocation.tool, invocation.action, invocation.resource_id,
                   dict(invocation.arguments).get("destination"))


@dataclass(frozen=True, slots=True)
class OutcomeObservation:
    decision: Decision
    dispatched: bool
    execution: Execution
    execution_reason: str | None
    lifecycle: str | None
    failed_writes: tuple[str, ...]
    timing: Timing

    @classmethod
    def from_result(cls, result: GatewayResult) -> "OutcomeObservation":
        return cls(result.decision, result.dispatched, result.execution, result.execution_reason,
                   result.lifecycle, result.failed_audit_events, result.timing)


@dataclass(frozen=True, slots=True)
class AttemptObservation:
    """One observed gateway entry, with or without a returned result."""

    run_id: str | None
    sequence: int
    mode: PolicyMode
    request_id: str | None = None
    binding: BindingObservation | None = None
    structural_valid: bool | None = None
    operation: OperationObservation | None = None
    outcome: OutcomeObservation | None = None
    before_versions: RecordVersions | None = None
    after_versions: RecordVersions | None = None
    effect: str | None = None
