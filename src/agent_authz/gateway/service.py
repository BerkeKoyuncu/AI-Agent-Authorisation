"""Enforce admission and dispatch in one ordered synthetic runtime."""

from collections.abc import Callable
from dataclasses import dataclass, field
from itertools import count
from threading import get_ident
from time import monotonic_ns

from ..audit import AUDIT_SCHEMA_VERSION
from ..delegation import DelegationManager, DelegationRecord, RuntimeExecutionContext
from ..identity.errors import AuthorityError, ErrorCode as AuthorityCode
from ..identity.principals import PrincipalKind
from ..identity.sessions import RunBinding, SessionManager, opaque_identifier, utc_now
from ..models import Action, Permission
from ..sandbox.environment import SandboxEnvironment
from ..sandbox.errors import SandboxError
from ..tasks import TASK_CATALOGUE
from .executor import _Executor
from .models import (
    POLICY_VERSION, Decision, Execution, GatewayResult, Invocation, PolicyMode, Reason, RecordVersions, Timing, ToolData,
)
from .policies import evaluate
from .registry import ValidationError, canonicalise


_AUTHORITY_DENIALS = {
    AuthorityCode.EXPIRED_DELEGATION: Reason.DELEGATION_EXPIRED,
    AuthorityCode.REVOKED_DELEGATION: Reason.DELEGATION_REVOKED,
    AuthorityCode.INVALID_TRANSITION: Reason.DELEGATION_INACTIVE,
    AuthorityCode.STALE_RECORD: Reason.STALE_RECORD,
    AuthorityCode.INSUFFICIENT_GRANTS: Reason.TASK_GRANTS_CHANGED,
}
_MUTATIONS = frozenset({Action.CREATE, Action.EDIT, Action.DELETE, Action.SEND})


@dataclass(slots=True)
class _Attempt:
    request_id: str
    start: int
    fields: dict[str, object] = field(default_factory=dict)
    audit_writes: list[tuple[str, int]] = field(default_factory=list)
    failed_events: list[str] = field(default_factory=list)
    policy_ns: int | None = None
    enforcement_ns: int | None = None
    executor_ns: int | None = None


class Gateway:
    """The controlled tool entry point. Configure one per single-threaded runtime."""

    def __init__(
        self, mode: PolicyMode, sessions: SessionManager, delegations: DelegationManager,
        sandbox: SandboxEnvironment, audit: Callable[[dict[str, object]], None], *,
        monotonic: Callable[[], int] = monotonic_ns,
        executor: Callable[[Invocation], ToolData] | None = None,
    ) -> None:
        if type(mode) is not PolicyMode:
            raise ValueError("A trusted policy mode is required.")
        self._mode = mode
        self._sessions = sessions
        self._delegations = delegations
        self._execute = _Executor(sandbox).execute if executor is None else executor
        self._audit = audit
        self._monotonic = monotonic
        self._owner = get_ident()
        self._busy = False
        self._namespace = opaque_identifier()
        self._requests = count(1)
        self._reserved_sends: set[str] = set()
        self._consumed_tasks: set[str] = set()
        self._uncertain_resources: set[str] = set()

    def handle(
        self, request: object, run: RunBinding, context: RuntimeExecutionContext | None = None,
    ) -> GatewayResult:
        start = self._monotonic()
        if get_ident() != self._owner or self._busy:
            attempt = _Attempt(opaque_identifier(), start, failed_events=["attempt"])
            attempt.enforcement_ns = self._monotonic() - start
            return self._result(attempt, Decision(self._mode, Reason.RUNTIME_UNAVAILABLE))

        self._busy = True
        try:
            attempt = _Attempt(f"{self._namespace}.{next(self._requests)}", start)
            return self._handle(attempt, request, run, context)
        finally:
            self._busy = False

    def _record(self, attempt: _Attempt, event: str, **fields: object) -> bool:
        record = {
            **attempt.fields, "schema_version": AUDIT_SCHEMA_VERSION, "event": event, "timestamp": utc_now().isoformat(),
            "request_id": attempt.request_id, "policy_mode": self._mode, "policy_version": POLICY_VERSION,
            "policy_ns": attempt.policy_ns, "enforcement_ns": attempt.enforcement_ns,
            "executor_ns": attempt.executor_ns, "prior_audit_writes_ns": tuple(attempt.audit_writes), **fields,
        }
        started = self._monotonic()
        try:
            self._audit(record)
        except Exception:
            attempt.failed_events.append(event)
            return False
        finally:
            attempt.audit_writes.append((event, self._monotonic() - started))
        return True

    @staticmethod
    def _decision_fields(decision: Decision) -> dict[str, object]:
        return {
            "allowed": decision.allowed, "reason": decision.reason,
            "human_version": decision.versions.human, "agent_version": decision.versions.agent,
            "delegation_version": decision.versions.delegation,
        }

    def _prepare_run(self, attempt: _Attempt, run: RunBinding) -> None:
        try:
            self._sessions.require_registered_run(run)
        except Exception:
            return
        attempt.fields.update(run_id=run.run_id, session_id=run.session_id,
                              human_id=run.human_id, agent_id=run.agent_id)

    def _evaluate(
        self, attempt: _Attempt, invocation: Invocation, run: RunBinding, context: RuntimeExecutionContext | None,
    ) -> tuple[Decision, DelegationRecord | None]:
        record = None
        versions = RecordVersions()
        try:
            self._sessions.require_registered_run(run)
            identities = self._sessions.identities
            human = identities.lookup(PrincipalKind.HUMAN, run.human_id)
            agent = identities.lookup(PrincipalKind.AGENT, run.agent_id)
            versions = RecordVersions(human.version, agent.version)
            self._sessions.validate_run(run)

            if self._mode is PolicyMode.C:
                if type(context) is not RuntimeExecutionContext or context.run is not run:
                    return Decision(self._mode, Reason.INVALID_CONTEXT, versions), None
                candidate = self._delegations.lookup(context.delegation_id)
                if candidate.run is run and candidate.task_id == context.task_id:
                    attempt.fields.update(task_id=candidate.task_id, delegation_id=candidate.delegation_id)
                    versions = RecordVersions(human.version, agent.version, candidate.version)
                record = self._delegations.validate_task_authority(context)

            decision = evaluate(self._mode, invocation, human, agent, record)
            if (decision.allowed and invocation.action in _MUTATIONS
                    and invocation.resource_id in self._uncertain_resources):
                decision = Decision(self._mode, Reason.MUTATION_UNCERTAIN, decision.versions)
            if decision.allowed and record is not None and (
                record.delegation_id in self._consumed_tasks or record.delegation_id in self._reserved_sends
            ):
                decision = Decision(self._mode, Reason.TASK_EFFECT_CONSUMED, decision.versions)
            return decision, record
        except AuthorityError as error:
            return Decision(self._mode, _AUTHORITY_DENIALS.get(error.code, Reason.INVALID_CONTEXT), versions), None
        except Exception:
            return Decision(self._mode, Reason.RUNTIME_UNAVAILABLE, versions), None

    def _handle(
        self, attempt: _Attempt, request: object, run: RunBinding, context: RuntimeExecutionContext | None,
    ) -> GatewayResult:
        validation_reason = None
        invocation = None
        try:
            invocation = canonicalise(request)
        except ValidationError as error:
            validation_reason = error.reason
        except Exception:
            validation_reason = Reason.RUNTIME_UNAVAILABLE

        if invocation is None:
            attempt.policy_ns = self._monotonic() - attempt.start
            preliminary = Decision(self._mode, validation_reason or Reason.RUNTIME_UNAVAILABLE)
        else:
            attempt.fields.update(tool=invocation.tool, action=invocation.action, resource_id=invocation.resource_id)
            if invocation.action is Action.SEND:
                attempt.fields["destination"] = dict(invocation.arguments)["destination"]
            preliminary, _ = self._evaluate(attempt, invocation, run, context)
            attempt.policy_ns = self._monotonic() - attempt.start
        self._prepare_run(attempt, run)

        if not self._record(attempt, "attempt") or not self._record(
            attempt, "validation", valid=invocation is not None, reason=validation_reason,
        ):
            return self._deny(attempt, Decision(self._mode, Reason.AUDIT_UNAVAILABLE, preliminary.versions))
        if invocation is None:
            return self._deny(attempt, preliminary)
        if not self._record(attempt, "preliminary", **self._decision_fields(preliminary)):
            return self._deny(attempt, Decision(self._mode, Reason.AUDIT_UNAVAILABLE, preliminary.versions))
        if not preliminary.allowed:
            return self._deny(attempt, preliminary)

        intended, _ = self._evaluate(attempt, invocation, run, context)
        if not intended.allowed:
            return self._deny(attempt, intended)
        if not self._record(attempt, "dispatch_intent", provisional=True, **self._decision_fields(intended)):
            return self._deny(attempt, Decision(self._mode, Reason.AUDIT_UNAVAILABLE, intended.versions))

        final, record = self._evaluate(attempt, invocation, run, context)
        if not final.allowed:
            return self._deny(attempt, final)
        return self._dispatch(attempt, invocation, final, record)

    def _deny(self, attempt: _Attempt, decision: Decision) -> GatewayResult:
        attempt.enforcement_ns = self._monotonic() - attempt.start
        self._record(attempt, "admission", dispatched=False, **self._decision_fields(decision))
        return self._result(attempt, decision)

    def _dispatch(
        self, attempt: _Attempt, invocation: Invocation, decision: Decision, record: DelegationRecord | None,
    ) -> GatewayResult:
        task = TASK_CATALOGUE[record.task_id] if record is not None else None
        reservation = None
        if record is not None and task is not None and task.max_successful_sends and invocation.action is Action.SEND:
            reservation = record.delegation_id
            self._reserved_sends.add(reservation)
        mutation = invocation.action in _MUTATIONS
        if mutation:
            self._uncertain_resources.add(invocation.resource_id)

        # Only a read of the trusted, side-effect-free timing source follows final admission.
        admitted = self._monotonic()
        attempt.enforcement_ns = admitted - attempt.start
        data = None
        execution_reason = None
        try:
            data = self._execute(invocation)
        except SandboxError as error:
            execution = Execution.FAILED
            execution_reason = error.code.name
        except Exception:
            execution = Execution.UNKNOWN
            execution_reason = "EXECUTOR_ERROR"
        except BaseException:
            if reservation is not None:
                self._reserved_sends.remove(reservation)
            raise
        else:
            execution = Execution.SUCCEEDED
        attempt.executor_ns = self._monotonic() - admitted

        lifecycle = self._after_execution(invocation, execution, record)
        if mutation and execution is not Execution.UNKNOWN:
            self._uncertain_resources.remove(invocation.resource_id)
        if reservation is not None:
            self._reserved_sends.remove(reservation)
        self._record(attempt, "admission", **self._decision_fields(decision))
        self._record(attempt, "dispatch", dispatched=True)
        self._record(attempt, "outcome", execution=execution, reason=execution_reason)
        if lifecycle is not None:
            self._record(attempt, "lifecycle", status=lifecycle, reserved_send=reservation is not None)
        return self._result(attempt, decision, execution, data, execution_reason, lifecycle)

    def _after_execution(
        self, invocation: Invocation, execution: Execution, record: DelegationRecord | None,
    ) -> str | None:
        if execution is Execution.UNKNOWN and invocation.action in _MUTATIONS:
            return "quarantined"
        if record is None:
            return None
        effect = Permission(invocation.action, invocation.resource_id)
        if TASK_CATALOGUE[record.task_id].completion_effect != effect:
            return None
        if execution is Execution.FAILED:
            return "failure_no_effect"
        if execution is not Execution.SUCCEEDED:
            return None

        self._consumed_tasks.add(record.delegation_id)
        try:
            return self._delegations.complete(record.delegation_id, successful_effect=effect).status.value
        except AuthorityError as error:
            if error.code is AuthorityCode.EXPIRED_DELEGATION:
                return "expired_after_effect"
            if error.code is AuthorityCode.REVOKED_DELEGATION:
                return "revoked_after_effect"
            return "completion_unavailable"
        except Exception:
            return "completion_unavailable"

    def _result(
        self, attempt: _Attempt, decision: Decision, execution: Execution = Execution.NOT_DISPATCHED,
        data: ToolData = None, execution_reason: str | None = None, lifecycle: str | None = None,
    ) -> GatewayResult:
        assert attempt.enforcement_ns is not None
        return GatewayResult(
            attempt.request_id, decision, execution, data, execution_reason, lifecycle, tuple(attempt.failed_events),
            Timing(attempt.policy_ns, attempt.enforcement_ns, attempt.executor_ns,
                   self._monotonic() - attempt.start - (attempt.executor_ns or 0), tuple(attempt.audit_writes)),
        )
