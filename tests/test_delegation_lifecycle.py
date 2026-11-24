from datetime import timedelta

import pytest

from agent_authz.delegation import DelegationStatus
from agent_authz.identity.errors import AuthorityError, ErrorCode
from agent_authz.models import Action, Permission
from agent_authz.tasks import TASK_CATALOGUE


def test_pending_and_active_authority_observe_exact_time_boundaries(runtime):
    _, run = runtime.start()
    manager = runtime.delegations
    start = runtime.clock.value + timedelta(minutes=1)
    end = start + timedelta(minutes=2)
    pending = manager.issue(run, "T1", valid_from=start, expires_at=end)
    delegation_id = pending.delegation_id
    with pytest.raises(AuthorityError) as no_authority:
        manager.bind_context(run, delegation_id)
    assert no_authority.value.code is ErrorCode.INVALID_TRANSITION

    runtime.clock.value = start - timedelta(microseconds=1)
    with pytest.raises(AuthorityError) as too_soon:
        manager.activate(run, delegation_id)
    assert too_soon.value.code is ErrorCode.INVALID_INTERVAL
    assert manager.lookup(delegation_id, expected_version=pending.version) is pending

    runtime.clock.value = start
    active = manager.activate(run, delegation_id)
    assert active.status is DelegationStatus.ACTIVE and active.version == pending.version + 1
    with pytest.raises(AuthorityError) as stale:
        manager.lookup(delegation_id, expected_version=pending.version)
    assert stale.value.code is ErrorCode.STALE_RECORD

    context = manager.bind_context(run, delegation_id)
    runtime.clock.value = end - timedelta(microseconds=1)
    assert manager.validate_task_authority(context) is active
    runtime.clock.value = end
    with pytest.raises(AuthorityError) as expired:
        manager.validate_task_authority(context)
    assert expired.value.code is ErrorCode.EXPIRED_DELEGATION
    assert runtime.sessions.validate_run(run) == end
    expired_record = manager.lookup(delegation_id)
    assert expired_record.status is DelegationStatus.EXPIRED and expired_record.version == active.version + 1

    runtime.clock.value = end + timedelta(microseconds=1)
    assert manager.lookup(delegation_id) is expired_record
    runtime.clock.value = start
    with pytest.raises(AuthorityError) as cannot_reactivate:
        manager.activate(run, delegation_id)
    assert cannot_reactivate.value.code is ErrorCode.EXPIRED_DELEGATION


def test_pending_delegation_can_expire_without_activation(runtime):
    _, run = runtime.start()
    manager = runtime.delegations
    pending = manager.issue(run, "T1")
    runtime.clock.value = pending.expires_at
    assert manager.lookup(pending.delegation_id).status is DelegationStatus.EXPIRED
    with pytest.raises(AuthorityError) as error:
        manager.activate(run, pending.delegation_id)
    assert error.value.code is ErrorCode.EXPIRED_DELEGATION


@pytest.mark.parametrize("activate_first", [False, True])
def test_revocation_is_terminal_and_keeps_shared_run_valid(runtime, activate_first):
    _, run = runtime.start()
    manager = runtime.delegations
    record = manager.issue(run, "T1")
    delegation_id = record.delegation_id
    if activate_first:
        record = manager.activate(run, delegation_id)
        context = manager.bind_context(run, delegation_id)
    revoked = manager.revoke(delegation_id)
    assert revoked.status is DelegationStatus.REVOKED and revoked.version == record.version + 1
    assert runtime.sessions.validate_run(run) == runtime.clock.value
    for operation in (
        lambda: manager.activate(run, delegation_id), lambda: manager.revoke(delegation_id),
        lambda: manager.bind_context(run, delegation_id), lambda: manager.complete(delegation_id),
    ):
        with pytest.raises(AuthorityError) as error:
            operation()
        assert error.value.code is ErrorCode.REVOKED_DELEGATION
    if activate_first:
        with pytest.raises(AuthorityError) as error:
            manager.validate_task_authority(context)
        assert error.value.code is ErrorCode.REVOKED_DELEGATION
    assert manager.lookup(delegation_id) is revoked


def test_completed_task_cannot_reactivate_or_reissue_in_same_run(runtime):
    _, run = runtime.start()
    manager = runtime.delegations
    pending = manager.issue(run, "T1")
    delegation_id = pending.delegation_id
    with pytest.raises(AuthorityError) as pending_completion:
        manager.complete(delegation_id)
    assert pending_completion.value.code is ErrorCode.INVALID_TRANSITION
    active = manager.activate(run, delegation_id)
    with pytest.raises(AuthorityError) as repeated_activation:
        manager.activate(run, delegation_id)
    assert repeated_activation.value.code is ErrorCode.INVALID_TRANSITION
    context = manager.bind_context(run, delegation_id)

    completed = manager.complete(delegation_id)
    assert completed.status is DelegationStatus.COMPLETED and completed.version == active.version + 1
    assert runtime.sessions.validate_run(run) == runtime.clock.value
    for operation in (
        lambda: manager.activate(run, delegation_id), lambda: manager.complete(delegation_id),
        lambda: manager.revoke(delegation_id), lambda: manager.validate_task_authority(context),
    ):
        with pytest.raises(AuthorityError) as terminal:
            operation()
        assert terminal.value.code is ErrorCode.INVALID_TRANSITION
    with pytest.raises(AuthorityError) as reuse:
        manager.issue(run, "T1")
    assert reuse.value.code is ErrorCode.INVALID_DELEGATION


@pytest.mark.parametrize(("task_id", "human", "agent", "action", "resource"), [
    ("T3", "alice", "document-agent", Action.CREATE, "summary.txt"),
    ("T4", "alice", "email-agent", Action.SEND, "email_outbox"),
    ("T5", "charlie", "document-agent", Action.DELETE, "summary.txt"),
])
def test_operational_completion_requires_the_designated_successful_effect(runtime, task_id, human, agent, action, resource):
    manager = runtime.delegations
    _, run = runtime.start(human, agent)
    definition = TASK_CATALOGUE[task_id]
    effect = Permission(action, resource)
    assert definition.completion_effect == effect
    assert definition.max_successful_sends == (1 if task_id == "T4" else None)

    pending = manager.issue(run, task_id)
    delegation_id = pending.delegation_id
    active = manager.activate(run, delegation_id)
    context = manager.bind_context(run, delegation_id)
    for wrong in (None, Permission(Action.READ, "meeting_notes.txt")):
        with pytest.raises(AuthorityError) as error:
            manager.complete(delegation_id, successful_effect=wrong)
        assert error.value.code is ErrorCode.INVALID_TRANSITION
        assert manager.lookup(delegation_id) is active

    assert manager.complete(delegation_id, successful_effect=effect).status is DelegationStatus.COMPLETED
    assert runtime.sessions.validate_run(run) == runtime.clock.value
    with pytest.raises(AuthorityError) as ended:
        manager.validate_task_authority(context)
    assert ended.value.code is ErrorCode.INVALID_TRANSITION
