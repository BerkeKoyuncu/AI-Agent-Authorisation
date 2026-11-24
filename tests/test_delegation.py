from datetime import datetime, timedelta, timezone

import pytest

from agent_authz.delegation import DEFAULT_DELEGATION_DURATION, DelegationStatus
from agent_authz.identity.errors import AuthorityError, ErrorCode
from agent_authz.identity.grants import Grant
from agent_authz.identity.principals import PrincipalKind
from agent_authz.models import Action, Permission
from agent_authz.tasks import TASK_CATALOGUE


TEAM = "team@example.invalid"
REVIEW = "review@example.invalid"

EXPECTED_TASKS = (
    ("T1", "alice", "document-agent", {(Action.READ, "meeting_notes.txt")}),
    ("T2", "bob", "document-agent", {(Action.READ, "financial_report.txt")}),
    ("T3", "alice", "document-agent", {(Action.READ, "meeting_notes.txt"), (Action.CREATE, "summary.txt")}),
    ("T4", "alice", "email-agent", {(Action.READ, "email_inbox"), (Action.SEND, "email_outbox")}),
    ("T5", "charlie", "document-agent", {(Action.DELETE, "summary.txt")}),
    ("T6", "alice", "document-agent", {(Action.READ, "meeting_notes.txt"), (Action.SEARCH, "meeting_notes.txt")}),
)


@pytest.mark.parametrize(("task_id", "human", "agent", "pairs"), EXPECTED_TASKS)
def test_all_approved_tasks_issue_and_activate_with_exact_grants(runtime, task_id, human, agent, pairs):
    assert set(TASK_CATALOGUE) == {task[0] for task in EXPECTED_TASKS}
    task = TASK_CATALOGUE[task_id]
    assert (task.human_id, task.agent_id) == (human, agent)
    assert {grant.permission for grant in task.grants} == {Permission(action, resource) for action, resource in pairs}
    for grant in task.grants:
        assert grant.destinations == (frozenset({TEAM}) if grant.permission.action is Action.SEND else None)

    _, run = runtime.start(human, agent)
    manager = runtime.delegations
    issued = manager.issue(run, task_id)
    assert issued.run is run and issued.grants == task.grants
    assert issued.status is DelegationStatus.PENDING and issued.version == 1
    assert issued.issued_at == issued.valid_from == runtime.clock.value
    assert issued.expires_at == issued.valid_from + DEFAULT_DELEGATION_DURATION
    active = manager.activate(run, issued.delegation_id)
    context = manager.bind_context(run, active.delegation_id)
    assert manager.validate_task_authority(context) is active


@pytest.mark.parametrize(("user", "agent"), [("bob", "document-agent"), ("alice", "email-agent")])
def test_wrong_human_or_agent_cannot_issue_task(runtime, user, agent):
    _, run = runtime.start(user, agent)
    with pytest.raises(AuthorityError) as error:
        runtime.delegations.issue(run, "T1")
    assert error.value.code is ErrorCode.BINDING_MISMATCH


@pytest.mark.parametrize(("kind", "principal"), [
    (PrincipalKind.HUMAN, "alice"), (PrincipalKind.AGENT, "document-agent"),
])
def test_missing_grants_prevent_issuance_and_activation(runtime, kind, principal):
    _, run = runtime.start()
    manager = runtime.delegations
    previous = runtime.identities.lookup(kind, principal)
    runtime.identities.replace_grants(kind, principal, frozenset())
    with pytest.raises(AuthorityError) as missing:
        manager.issue(run, "T1")
    assert missing.value.code is ErrorCode.INSUFFICIENT_GRANTS

    runtime.identities.replace_grants(kind, principal, previous.grants)
    record = manager.issue(run, "T1")
    runtime.identities.replace_grants(kind, principal, frozenset())
    with pytest.raises(AuthorityError) as cannot_activate:
        manager.activate(run, record.delegation_id)
    assert cannot_activate.value.code is ErrorCode.INSUFFICIENT_GRANTS
    assert manager.lookup(record.delegation_id) is record


def test_unknown_tasks_and_excessive_grants_leave_run_available(runtime):
    _, run = runtime.start()
    manager = runtime.delegations
    with pytest.raises(AuthorityError) as unknown:
        manager.issue(run, "T7")
    assert unknown.value.code is ErrorCode.UNKNOWN_TASK
    extra = Grant(Permission(Action.READ, "public_report.txt"))
    with pytest.raises(AuthorityError) as excessive:
        manager.issue(run, "T1", grants=TASK_CATALOGUE["T1"].grants | {extra})
    assert excessive.value.code is ErrorCode.INSUFFICIENT_GRANTS
    with pytest.raises(AuthorityError) as invalid:
        manager.issue(run, "T1", grants=frozenset({extra.permission}))
    assert invalid.value.code is ErrorCode.INVALID_GRANT
    assert manager.issue(run, "T1").status is DelegationStatus.PENDING


@pytest.mark.parametrize(("kind", "principal"), [
    (PrincipalKind.HUMAN, "alice"), (PrincipalKind.AGENT, "email-agent"),
])
def test_send_constraints_cannot_exceed_template_or_either_principal(runtime, kind, principal):
    _, run = runtime.start("alice", "email-agent")
    manager = runtime.delegations
    pair = Permission(Action.SEND, "email_outbox")
    team_only = Grant(pair, frozenset({TEAM}))
    review_only = Grant(pair, frozenset({REVIEW}))
    both_routes = Grant(pair, frozenset({TEAM, REVIEW}))
    with pytest.raises(AuthorityError) as wider:
        manager.issue(run, "T4", grants=frozenset({both_routes}))
    assert wider.value.code is ErrorCode.INSUFFICIENT_GRANTS

    original = runtime.identities.lookup(kind, principal)
    runtime.identities.replace_grants(kind, principal, (original.grants - {both_routes}) | {review_only})
    with pytest.raises(AuthorityError) as wrong_route:
        manager.issue(run, "T4", grants=frozenset({team_only}))
    assert wrong_route.value.code is ErrorCode.INSUFFICIENT_GRANTS
    runtime.identities.replace_grants(kind, principal, original.grants)
    record = manager.issue(run, "T4", grants=frozenset({team_only}))
    assert record.grants == frozenset({team_only})


def test_narrowing_keeps_search_read_pair_and_completion_effect(runtime):
    _, run = runtime.start()
    search = Grant(Permission(Action.SEARCH, "meeting_notes.txt"))
    only_read = frozenset({Grant(Permission(Action.READ, "meeting_notes.txt"))})
    for task, grants in (("T6", frozenset({search})), ("T6", frozenset()), ("T3", only_read)):
        with pytest.raises(AuthorityError) as error:
            runtime.delegations.issue(run, task, grants=grants)
        assert error.value.code is ErrorCode.INSUFFICIENT_GRANTS
    assert runtime.delegations.issue(run, "T6", grants=only_read).grants == only_read


def test_invalid_intervals_leave_no_delegation(runtime):
    _, run = runtime.start()
    now = runtime.clock.value
    for interval in (
        {"valid_from": now.replace(tzinfo=None)},
        {"valid_from": now.replace(fold=1)},
        {"valid_from": now - timedelta(seconds=1)},
        {"expires_at": now},
        {"expires_at": now.astimezone(timezone(timedelta(hours=1)))},
        {"valid_from": datetime.max.replace(tzinfo=timezone.utc)},
    ):
        with pytest.raises(AuthorityError) as error:
            runtime.delegations.issue(run, "T1", **interval)
        assert error.value.code is ErrorCode.INVALID_INTERVAL
    assert runtime.delegations.issue(run, "T1").version == 1
