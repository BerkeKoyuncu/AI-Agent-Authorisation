"""Issue, bind and validate synthetic task authority in the trusted runtime."""

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum

from .identity.errors import AuthorityError, ErrorCode
from .identity.grants import Grant, covers_grants, validate_grants
from .identity.principals import PrincipalKind
from .identity.sessions import RunBinding, SessionManager, expires_after, opaque_identifier, require_utc
from .models import Action, Permission
from .tasks import TASK_CATALOGUE, TaskDefinition


DEFAULT_DELEGATION_DURATION = timedelta(minutes=5)


class DelegationStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    EXPIRED = "expired"
    REVOKED = "revoked"


_LIVE_STATUSES = frozenset({DelegationStatus.PENDING, DelegationStatus.ACTIVE})


@dataclass(frozen=True, slots=True)
class DelegationRecord:
    delegation_id: str
    task_id: str
    run: RunBinding
    grants: frozenset[Grant]
    status: DelegationStatus
    issued_at: datetime
    valid_from: datetime
    expires_at: datetime
    version: int = 1


@dataclass(frozen=True, slots=True)
class RuntimeExecutionContext:
    run: RunBinding
    task_id: str
    delegation_id: str
    human_version: int
    agent_version: int
    delegation_version: int


class DelegationManager:
    """Own delegation and execution-context records for one trusted runtime."""

    def __init__(
        self, sessions: SessionManager, *, new_id: Callable[[], str] = opaque_identifier,
    ) -> None:
        self._sessions = sessions
        self._new_id = new_id
        self._records: dict[str, DelegationRecord] = {}
        self._delegated_runs: set[str] = set()
        self._contexts: dict[str, RuntimeExecutionContext] = {}

    def _principal_versions(self, run: RunBinding, grants: frozenset[Grant]) -> tuple[int, int]:
        identities = self._sessions.identities
        human = identities.require_enabled(PrincipalKind.HUMAN, run.human_id)
        agent = identities.require_enabled(PrincipalKind.AGENT, run.agent_id)
        if not covers_grants(human.grants, grants) or not covers_grants(agent.grants, grants):
            raise AuthorityError(ErrorCode.INSUFFICIENT_GRANTS)
        return human.version, agent.version

    def issue(
        self,
        run: RunBinding,
        task_id: str,
        *,
        grants: frozenset[Grant] | None = None,
        valid_from: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> DelegationRecord:
        """Issue a pending record for an already registered run."""
        now = self._sessions.validate_run(run)
        task = TASK_CATALOGUE.get(task_id) if type(task_id) is str else None
        if task is None:
            raise AuthorityError(ErrorCode.UNKNOWN_TASK)
        self._check_task_binding(run, task)
        if run.run_id in self._delegated_runs:
            raise AuthorityError(ErrorCode.INVALID_DELEGATION)

        requested = task.grants if grants is None else grants
        validate_grants(requested)
        self._principal_versions(run, requested)
        if not covers_grants(task.grants, requested):
            raise AuthorityError(ErrorCode.INSUFFICIENT_GRANTS)
        self._check_required_grants(task, requested)

        start = now if valid_from is None else require_utc(valid_from)
        end = expires_after(start, DEFAULT_DELEGATION_DURATION) if expires_at is None else require_utc(expires_at)
        if not now <= start < end:
            raise AuthorityError(ErrorCode.INVALID_INTERVAL)

        delegation_id = self._new_id()
        if type(delegation_id) is not str or not delegation_id:
            raise AuthorityError(ErrorCode.INVALID_ARGUMENT)
        if delegation_id in self._records:
            raise AuthorityError(ErrorCode.IDENTIFIER_COLLISION)
        record = DelegationRecord(delegation_id, task_id, run, requested, DelegationStatus.PENDING, now, start, end)
        self._records[delegation_id] = record
        self._delegated_runs.add(run.run_id)
        return record

    @staticmethod
    def _check_task_binding(run: RunBinding, task: TaskDefinition) -> None:
        if (task.human_id, task.agent_id) != (run.human_id, run.agent_id):
            raise AuthorityError(ErrorCode.BINDING_MISMATCH)

    @staticmethod
    def _check_required_grants(task: TaskDefinition, grants: frozenset[Grant]) -> None:
        pairs = {grant.permission for grant in grants}
        if not pairs or (task.completion_effect is not None and task.completion_effect not in pairs):
            raise AuthorityError(ErrorCode.INSUFFICIENT_GRANTS)
        if any(
            pair.action is Action.SEARCH and Permission(Action.READ, pair.resource_id) not in pairs
            for pair in pairs
        ):
            raise AuthorityError(ErrorCode.INSUFFICIENT_GRANTS)

    def _transition(self, record: DelegationRecord, status: DelegationStatus) -> DelegationRecord:
        updated = replace(record, status=status, version=record.version + 1)
        self._records[record.delegation_id] = updated
        return updated

    def _lookup(self, delegation_id: str, now: datetime) -> DelegationRecord:
        record = self._records.get(delegation_id) if type(delegation_id) is str else None
        if record is None:
            raise AuthorityError(ErrorCode.INVALID_DELEGATION)
        if now >= record.expires_at and record.status in _LIVE_STATUSES:
            record = self._transition(record, DelegationStatus.EXPIRED)
        return record

    def lookup(self, delegation_id: str, *, expected_version: int | None = None) -> DelegationRecord:
        record = self._lookup(delegation_id, self._sessions.now())
        if expected_version is not None and (type(expected_version) is not int or expected_version != record.version):
            raise AuthorityError(ErrorCode.STALE_RECORD)
        return record

    def _require_bound(self, run: RunBinding, delegation_id: str, now: datetime) -> DelegationRecord:
        record = self._lookup(delegation_id, now)
        if record.run is not run:
            raise AuthorityError(ErrorCode.BINDING_MISMATCH)
        self._check_task_binding(run, TASK_CATALOGUE[record.task_id])
        return record

    @staticmethod
    def _require_status(record: DelegationRecord, allowed: frozenset[DelegationStatus]) -> None:
        if record.status is DelegationStatus.EXPIRED:
            raise AuthorityError(ErrorCode.EXPIRED_DELEGATION)
        if record.status is DelegationStatus.REVOKED:
            raise AuthorityError(ErrorCode.REVOKED_DELEGATION)
        if record.status not in allowed:
            raise AuthorityError(ErrorCode.INVALID_TRANSITION)

    def activate(self, run: RunBinding, delegation_id: str) -> DelegationRecord:
        now = self._sessions.validate_run(run)
        record = self._require_bound(run, delegation_id, now)
        self._require_status(record, frozenset({DelegationStatus.PENDING}))
        if now < record.valid_from:
            raise AuthorityError(ErrorCode.INVALID_INTERVAL)
        self._principal_versions(run, record.grants)
        return self._transition(record, DelegationStatus.ACTIVE)

    def revoke(self, delegation_id: str) -> DelegationRecord:
        record = self.lookup(delegation_id)
        self._require_status(record, _LIVE_STATUSES)
        return self._transition(record, DelegationStatus.REVOKED)

    def complete(self, delegation_id: str, *, successful_effect: Permission | None = None) -> DelegationRecord:
        """Record trusted operational completion without executing a tool."""
        now = self._sessions.now()
        record = self._lookup(delegation_id, now)
        self._require_status(record, frozenset({DelegationStatus.ACTIVE}))
        if now < record.valid_from:
            raise AuthorityError(ErrorCode.INVALID_INTERVAL)
        expected = TASK_CATALOGUE[record.task_id].completion_effect
        if successful_effect is not None and (
            type(successful_effect) is not Permission or type(successful_effect.action) is not Action
            or type(successful_effect.resource_id) is not str
        ):
            raise AuthorityError(ErrorCode.INVALID_ARGUMENT)
        if expected != successful_effect:
            raise AuthorityError(ErrorCode.INVALID_TRANSITION)
        return self._transition(record, DelegationStatus.COMPLETED)

    def _active_authority(self, run: RunBinding, delegation_id: str) -> tuple[DelegationRecord, int, int]:
        now = self._sessions.validate_run(run)
        record = self._require_bound(run, delegation_id, now)
        self._require_status(record, frozenset({DelegationStatus.ACTIVE}))
        if now < record.valid_from:
            raise AuthorityError(ErrorCode.INVALID_INTERVAL)
        human_version, agent_version = self._principal_versions(run, record.grants)
        return record, human_version, agent_version

    def bind_context(self, run: RunBinding, delegation_id: str) -> RuntimeExecutionContext:
        record, human_version, agent_version = self._active_authority(run, delegation_id)
        context = RuntimeExecutionContext(
            run, record.task_id, delegation_id, human_version, agent_version, record.version,
        )
        current = self._contexts.get(delegation_id)
        if current is not None and current == context:
            return current
        self._contexts[delegation_id] = context
        return context

    def validate_task_authority(self, context: RuntimeExecutionContext) -> DelegationRecord:
        if type(context) is not RuntimeExecutionContext:
            raise AuthorityError(ErrorCode.BINDING_MISMATCH)
        record, human_version, agent_version = self._active_authority(context.run, context.delegation_id)
        if context.task_id != record.task_id:
            raise AuthorityError(ErrorCode.BINDING_MISMATCH)
        if (context.human_version, context.agent_version, context.delegation_version) != (
            human_version, agent_version, record.version,
        ):
            raise AuthorityError(ErrorCode.STALE_RECORD)
        if self._contexts.get(record.delegation_id) is not context:
            raise AuthorityError(ErrorCode.BINDING_MISMATCH)
        return record
