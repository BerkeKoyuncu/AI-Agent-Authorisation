from dataclasses import replace
from datetime import timedelta

import pytest

from agent_authz.delegation import DelegationManager
from agent_authz.identity.errors import AuthorityError, ErrorCode
from agent_authz.identity.principals import PrincipalKind
from agent_authz.identity.sessions import SessionManager


def bind_t1(runtime, run):
    manager = runtime.delegations
    pending = manager.issue(run, "T1")
    active = manager.activate(run, pending.delegation_id)
    return manager.bind_context(run, active.delegation_id)


def test_context_binds_registered_identity_session_task_and_run(runtime):
    token, run = runtime.start()
    context = bind_t1(runtime, run)
    manager = runtime.delegations
    assert context.run is run
    assert run.human_id == "alice" and run.agent_id == "document-agent"
    assert run.session_id == runtime.sessions.validate_session(token).session_id
    assert context.task_id == "T1" and context.delegation_version == 2
    assert token not in repr(context)
    record = manager.validate_task_authority(context)
    assert record.run is run and record.task_id == context.task_id
    assert record.delegation_id == context.delegation_id
    assert manager.bind_context(run, record.delegation_id) is context


def test_fabricated_context_and_modified_binding_fields_fail(runtime):
    _, run = runtime.start()
    context = bind_t1(runtime, run)
    for fabricated in (
        replace(context), replace(context, task_id="T2"),
        replace(context, run=replace(run, human_id="bob")),
        replace(context, run=replace(run, agent_id="email-agent")),
        replace(context, run=replace(run, session_id="other-session")),
        replace(context, run=replace(run, run_id="other-run")),
        replace(context, run=replace(run)),
    ):
        with pytest.raises(AuthorityError) as error:
            runtime.delegations.validate_task_authority(fabricated)
        assert error.value.code is ErrorCode.BINDING_MISMATCH
    with pytest.raises(AuthorityError) as unknown_delegation:
        runtime.delegations.validate_task_authority(replace(context, delegation_id="other-delegation"))
    assert unknown_delegation.value.code is ErrorCode.INVALID_DELEGATION


def test_each_run_requires_its_own_delegation_even_in_the_same_session(runtime):
    token, first_run = runtime.start()
    _, other_session_run = runtime.start()
    second_run = runtime.sessions.start_run(token, "document-agent")
    first = bind_t1(runtime, first_run)
    second = bind_t1(runtime, second_run)
    assert first_run.session_id == second_run.session_id
    assert first_run.run_id != second_run.run_id and first.delegation_id != second.delegation_id

    manager = runtime.delegations
    for wrong_run in (second_run, other_session_run):
        with pytest.raises(AuthorityError) as bind_failure:
            manager.bind_context(wrong_run, first.delegation_id)
        assert bind_failure.value.code is ErrorCode.BINDING_MISMATCH
        with pytest.raises(AuthorityError) as activate_failure:
            manager.activate(wrong_run, first.delegation_id)
        assert activate_failure.value.code is ErrorCode.BINDING_MISMATCH

    with pytest.raises(AuthorityError) as swapped:
        manager.validate_task_authority(replace(first, delegation_id=second.delegation_id))
    assert swapped.value.code is ErrorCode.BINDING_MISMATCH


@pytest.mark.parametrize(("kind", "principal"), [
    (PrincipalKind.HUMAN, "alice"), (PrincipalKind.AGENT, "document-agent"),
])
def test_grant_reduction_invalidates_task_authority_without_closing_shared_run(runtime, kind, principal):
    _, run = runtime.start()
    context = bind_t1(runtime, run)
    identities = runtime.identities
    prior = identities.lookup(kind, principal)
    identities.replace_grants(kind, principal, frozenset())
    for check in (lambda: runtime.delegations.validate_task_authority(context),
                  lambda: runtime.delegations.bind_context(run, context.delegation_id)):
        with pytest.raises(AuthorityError) as error:
            check()
        assert error.value.code is ErrorCode.INSUFFICIENT_GRANTS
    assert runtime.sessions.validate_run(run) == runtime.clock.value

    identities.replace_grants(kind, principal, prior.grants)
    with pytest.raises(AuthorityError) as stale:
        runtime.delegations.validate_task_authority(context)
    assert stale.value.code is ErrorCode.STALE_RECORD
    updated = runtime.delegations.bind_context(run, context.delegation_id)
    assert updated is not context
    assert runtime.delegations.validate_task_authority(updated).run is run


@pytest.mark.parametrize(("kind", "principal"), [
    (PrincipalKind.HUMAN, "alice"), (PrincipalKind.AGENT, "document-agent"),
])
def test_disabling_a_principal_blocks_both_shared_run_and_task_authority(runtime, kind, principal):
    _, run = runtime.start()
    context = bind_t1(runtime, run)
    runtime.identities.disable(kind, principal)
    for check in (lambda: runtime.sessions.validate_run(run), lambda: runtime.delegations.validate_task_authority(context)):
        with pytest.raises(AuthorityError) as error:
            check()
        assert error.value.code is ErrorCode.DISABLED_IDENTITY


def test_session_invalidation_blocks_shared_run_and_task_authority(runtime):
    token, run = runtime.start()
    context = bind_t1(runtime, run)
    runtime.sessions.invalidate(token)
    for check in (lambda: runtime.sessions.validate_run(run), lambda: runtime.delegations.validate_task_authority(context)):
        with pytest.raises(AuthorityError) as error:
            check()
        assert error.value.code is ErrorCode.INVALID_SESSION


def test_session_expiry_blocks_authority_even_if_delegation_interval_is_still_valid(runtime):
    token, run = runtime.start()
    session = runtime.sessions.validate_session(token)
    manager = runtime.delegations
    pending = manager.issue(run, "T1", expires_at=session.expires_at + timedelta(minutes=1))
    active = manager.activate(run, pending.delegation_id)
    context = manager.bind_context(run, active.delegation_id)

    runtime.clock.value = session.expires_at
    assert manager.lookup(active.delegation_id) is active
    with pytest.raises(AuthorityError) as expired:
        manager.validate_task_authority(context)
    assert expired.value.code is ErrorCode.EXPIRED_SESSION
    with pytest.raises(AuthorityError) as no_run:
        runtime.sessions.validate_run(run)
    assert no_run.value.code is ErrorCode.INVALID_SESSION


def test_runtime_instances_reject_each_others_handles(runtime):
    token, run = runtime.start()
    context = bind_t1(runtime, run)
    independent = SessionManager(runtime.identities)
    with pytest.raises(AuthorityError) as no_session:
        independent.validate_session(token)
    assert no_session.value.code is ErrorCode.INVALID_SESSION
    with pytest.raises(AuthorityError) as no_run:
        independent.validate_run(run)
    assert no_run.value.code is ErrorCode.BINDING_MISMATCH
    with pytest.raises(AuthorityError) as no_context:
        DelegationManager(runtime.sessions).validate_task_authority(context)
    assert no_context.value.code is ErrorCode.INVALID_DELEGATION
