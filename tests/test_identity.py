from dataclasses import FrozenInstanceError
from datetime import timedelta

import pytest

from agent_authz.identity.errors import AuthorityError, ErrorCode
from agent_authz.identity.grants import Grant
from agent_authz.identity.principals import PRINCIPAL_FIXTURES, IdentityStore, PrincipalKind
from agent_authz.identity.sessions import SESSION_DURATION, SessionManager
from agent_authz.models import Action, Permission


HUMAN = PrincipalKind.HUMAN
AGENT = PrincipalKind.AGENT
TEAM = "team@example.invalid"
REVIEW = "review@example.invalid"


def test_principal_fixtures_match_approved_matrices(runtime):
    expected = {
        (HUMAN, "alice"): ("Employee", ["rs", "rs", "", "", "rc", "r", "m"]),
        (HUMAN, "bob"): ("Manager", ["rs", "rse", "rs", "", "", "", ""]),
        (HUMAN, "charlie"): ("Administrator", ["rs", "rs", "rs", "rs", "rd", "", ""]),
        (AGENT, "document-agent"): ("Document Agent", ["rs", "rse", "rs", "", "rcd", "", ""]),
        (AGENT, "email-agent"): ("Email Agent", ["", "", "", "", "", "r", "m"]),
    }
    resources = (
        "meeting_notes.txt", "public_report.txt", "financial_report.txt", "salary_data.txt",
        "summary.txt", "email_inbox", "email_outbox",
    )
    actions = dict(zip("rscedm", (Action.READ, Action.SEARCH, Action.CREATE, Action.EDIT, Action.DELETE, Action.SEND)))
    assert {(record.kind, record.principal_id) for record in PRINCIPAL_FIXTURES} == set(expected)
    for (kind, principal_id), (label, matrix) in expected.items():
        record = runtime.identities.lookup(kind, principal_id)
        assert (record.label, record.enabled, record.version) == (label, True, 1)
        assert record.grants == frozenset(
            Grant(Permission(actions[action], resource), frozenset({TEAM, REVIEW}) if action == "m" else None)
            for resource, cell in zip(resources, matrix, strict=True) for action in cell
        )


def test_identity_changes_are_versioned_and_isolated(runtime):
    old = runtime.identities.lookup(HUMAN, "alice")
    with pytest.raises(FrozenInstanceError):
        old.grants = frozenset()
    new = runtime.identities.replace_grants(HUMAN, "alice", frozenset())
    assert new.version == old.version + 1
    assert old.grants and not new.grants
    assert IdentityStore().lookup(HUMAN, "alice") == old
    with pytest.raises(AuthorityError) as stale:
        runtime.identities.lookup(HUMAN, "alice", expected_version=old.version)
    assert stale.value.code is ErrorCode.STALE_RECORD

    disabled = runtime.identities.disable(HUMAN, "alice")
    assert not disabled.enabled and disabled.version == new.version + 1
    with pytest.raises(AuthorityError) as rejected:
        runtime.identities.require_enabled(HUMAN, "alice")
    assert rejected.value.code is ErrorCode.DISABLED_IDENTITY


def test_duplicates_and_unknown_principals_are_rejected(runtime):
    principal = PRINCIPAL_FIXTURES[0]
    with pytest.raises(AuthorityError) as duplicate:
        IdentityStore((principal, principal))
    assert duplicate.value.code is ErrorCode.DUPLICATE_IDENTITY
    with pytest.raises(AuthorityError) as missing:
        runtime.identities.lookup(AGENT, "alice")
    assert missing.value.code is ErrorCode.UNKNOWN_IDENTITY


@pytest.mark.parametrize(("action", "resource"), [
    (Action.SEND, "meeting_notes.txt"), (Action.DELETE, "email_inbox"), (Action.SEARCH, "email_outbox"),
    (Action.READ, "unregistered.txt"), ("read", "meeting_notes.txt"), (Action.READ, "*"),
])
def test_grants_require_supported_exact_pairs(action, resource):
    with pytest.raises(AuthorityError) as error:
        Grant(Permission(action, resource))
    assert error.value.code is ErrorCode.INVALID_GRANT


@pytest.mark.parametrize("constraint", [None, frozenset(), frozenset({"other@example.invalid"}), {TEAM}])
def test_send_requires_explicit_nonempty_registered_route_constraints(constraint):
    with pytest.raises(AuthorityError) as error:
        Grant(Permission(Action.SEND, "email_outbox"), constraint)
    assert error.value.code is ErrorCode.INVALID_CONSTRAINT


def test_ambiguous_or_mutable_grants_cannot_replace_identity_permissions(runtime):
    before = runtime.identities.lookup(HUMAN, "alice")
    pair = Permission(Action.SEND, "email_outbox")
    duplicates = frozenset({Grant(pair, frozenset({TEAM})), Grant(pair, frozenset({REVIEW}))})
    with pytest.raises(AuthorityError) as duplicate:
        runtime.identities.replace_grants(HUMAN, "alice", duplicates)
    assert duplicate.value.code is ErrorCode.INVALID_CONSTRAINT
    with pytest.raises(AuthorityError) as mutable:
        runtime.identities.replace_grants(HUMAN, "alice", set(before.grants))
    assert mutable.value.code is ErrorCode.INVALID_GRANT
    with pytest.raises(AuthorityError) as constrained_read:
        Grant(Permission(Action.READ, "email_inbox"), frozenset({TEAM}))
    assert constrained_read.value.code is ErrorCode.INVALID_CONSTRAINT
    assert runtime.identities.lookup(HUMAN, "alice") is before


def test_authentication_binds_distinct_sessions_without_returning_secrets_in_records(runtime):
    sessions = runtime.sessions
    proof = sessions.provision_credential("alice")
    first = sessions.authenticate("alice", proof)
    second = sessions.authenticate("alice", proof)
    assert first != second
    session = sessions.validate_session(first)
    run = sessions.start_run(first, "document-agent")
    assert session.human_id == run.human_id == "alice"
    assert session.session_id == run.session_id != sessions.validate_session(second).session_id
    assert session.session_id != first
    assert all(secret not in repr(session) + repr(run) for secret in (proof, first, second))


@pytest.mark.parametrize("proof", ["alice", "invalid-proof", "", None, "é"])
def test_invalid_proofs_do_not_authenticate(runtime, proof):
    runtime.sessions.provision_credential("alice")
    with pytest.raises(AuthorityError) as error:
        runtime.sessions.authenticate("alice", proof)
    assert error.value.code is ErrorCode.INVALID_PROOF
    assert str(error.value) == "invalid authentication proof"


def test_unknown_unprovisioned_and_disabled_humans_cannot_authenticate(runtime):
    proof = runtime.sessions.provision_credential("alice")
    with pytest.raises(AuthorityError) as unknown:
        runtime.sessions.authenticate("unknown", proof)
    assert unknown.value.code is ErrorCode.UNKNOWN_IDENTITY
    assert proof not in str(unknown.value)
    with pytest.raises(AuthorityError) as unprovisioned:
        runtime.sessions.authenticate("bob", proof)
    assert unprovisioned.value.code is ErrorCode.INVALID_PROOF
    token = runtime.sessions.authenticate("alice", proof)
    runtime.identities.disable(HUMAN, "alice")
    for check in (lambda: runtime.sessions.authenticate("alice", proof), lambda: runtime.sessions.validate_session(token)):
        with pytest.raises(AuthorityError) as disabled:
            check()
        assert disabled.value.code is ErrorCode.DISABLED_IDENTITY
        assert token not in str(disabled.value) and proof not in str(disabled.value)


def test_reprovisioning_replaces_proof_without_switching_existing_session_identity(runtime):
    sessions = runtime.sessions
    original = sessions.provision_credential("alice")
    token = sessions.authenticate("alice", original)
    current = sessions.provision_credential("alice")
    sessions.provision_credential("bob")

    for human_id, proof in (("alice", original), ("bob", current)):
        with pytest.raises(AuthorityError) as error:
            sessions.authenticate(human_id, proof)
        assert error.value.code is ErrorCode.INVALID_PROOF
    assert sessions.validate_session(token).human_id == "alice"
    with pytest.raises(AuthorityError) as unknown_agent:
        sessions.start_run(token, "unregistered-agent")
    assert unknown_agent.value.code is ErrorCode.UNKNOWN_IDENTITY


def test_session_expiry_boundary_and_invalidation(runtime):
    token, _ = runtime.start()
    other, _ = runtime.start()
    initial = runtime.sessions.validate_session(token)
    assert initial.expires_at == runtime.clock.value + SESSION_DURATION
    runtime.sessions.invalidate(other)
    for invalid in (None, "fabricated-token", other, initial.session_id):
        with pytest.raises(AuthorityError) as error:
            runtime.sessions.validate_session(invalid)
        assert error.value.code is ErrorCode.INVALID_SESSION
        assert str(error.value) == "invalid session"

    runtime.clock.value = initial.expires_at - timedelta(microseconds=1)
    assert runtime.sessions.validate_session(token) is initial
    runtime.clock.value = initial.expires_at
    with pytest.raises(AuthorityError) as expired:
        runtime.sessions.validate_session(token)
    assert expired.value.code is ErrorCode.EXPIRED_SESSION
    runtime.clock.value = initial.issued_at
    with pytest.raises(AuthorityError) as closed:
        runtime.sessions.validate_session(token)
    assert closed.value.code is ErrorCode.INVALID_SESSION


def test_session_factory_collisions_cannot_create_partial_sessions():
    source = iter(("proof", "session-ref", "session-ref", "new-session-ref", "new-token"))
    sessions = SessionManager(IdentityStore(), new_id=lambda: next(source))
    proof = sessions.provision_credential("alice")
    with pytest.raises(AuthorityError) as error:
        sessions.authenticate("alice", proof)
    assert error.value.code is ErrorCode.IDENTIFIER_COLLISION
    with pytest.raises(AuthorityError) as invalid:
        sessions.validate_session("session-ref")
    assert invalid.value.code is ErrorCode.INVALID_SESSION
    assert sessions.validate_session(sessions.authenticate("alice", proof)).human_id == "alice"
