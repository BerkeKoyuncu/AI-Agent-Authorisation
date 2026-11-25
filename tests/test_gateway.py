from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from agent_authz.delegation import DelegationStatus
from agent_authz.gateway import Execution, Gateway, PolicyMode
from agent_authz.gateway import service
from agent_authz.gateway.audit import JsonlAudit
from agent_authz.gateway.executor import _Executor
from agent_authz.gateway.models import Reason
from agent_authz.gateway.policies import evaluate
from agent_authz.gateway.registry import canonicalise
from agent_authz.identity.principals import PrincipalKind
from agent_authz.models import Action
from agent_authz.sandbox import Fixture, SandboxEnvironment
from agent_authz.sandbox.errors import ErrorCode, SandboxError
from agent_authz.sandbox.fixtures import AGENDA_LINE, EXPECTED_SUMMARY
from agent_authz.tasks import TASK_CATALOGUE


TEAM = "team@example.invalid"
REVIEW = "review@example.invalid"


def request(tool, resource, **arguments):
    return {"tool": tool, "arguments": {"resource_id": resource, **arguments}}


def send(destination=TEAM):
    return request("send_simulated_email", "email_outbox", destination=destination,
                   subject="Synthetic subject marker", body="Synthetic body marker")


MEETING = request("read_document", "meeting_notes.txt")


@pytest.fixture
def lab(runtime):
    def build(mode, task_id="T1", *, fixture=Fixture.SUMMARY_ABSENT,
              audit_hook=None, executor_hook=None, **options):
        task = TASK_CATALOGUE[task_id]
        proof = runtime.sessions.provision_credential(task.human_id)
        token = runtime.sessions.authenticate(task.human_id, proof)
        run = runtime.sessions.start_run(token, task.agent_id)
        pending = runtime.delegations.issue(run, task_id)
        active = runtime.delegations.activate(run, pending.delegation_id)
        context = runtime.delegations.bind_context(run, pending.delegation_id)
        sandbox = SandboxEnvironment(fixture)
        execute = _Executor(sandbox).execute
        events, invocations = [], []

        def audit(event):
            if audit_hook is not None:
                audit_hook(event)
            events.append(event)

        def executor(invocation):
            invocations.append(invocation)
            if executor_hook is not None:
                return executor_hook(invocation, execute)
            return execute(invocation)

        gateway = Gateway(mode, runtime.sessions, runtime.delegations, sandbox, audit, executor=executor, **options)
        return SimpleNamespace(
            gateway=gateway, sandbox=sandbox, events=events, invocations=invocations,
            token=token, proof=proof, run=run, context=context, active=active,
            call=lambda raw: gateway.handle(raw, run, context),
        )
    return build


@pytest.mark.parametrize("mode", list(PolicyMode))
@pytest.mark.parametrize(("task", "raw", "condition", "expected"), [
    ("T1", MEETING, "normal", (True, True, True)),
    ("T1", request("read_document", "public_report.txt"), "normal", (True, True, False)),
    ("T2", request("read_document", "salary_data.txt"), "normal", (True, True, False)),
    ("T4", send(), "normal", (True, True, True)),
    ("T4", send(REVIEW), "normal", (True, True, False)),
    ("T2", request("edit_document", "public_report.txt", content="Changed"), "normal", (True, False, False)),
    ("T1", request("delete_document", "summary.txt"), "normal", (True, True, False)),
    ("T1", {"tool": "extend_delegation", "arguments": {}}, "normal", (False, False, False)),
    ("T1", {**MEETING, "human_id": "charlie"}, "normal", (False, False, False)),
    ("T6", request("search_documents", "meeting_notes.txt", query="agenda"), "normal", (True, True, True)),
    ("T1", request("search_documents", "public_report.txt", query="inventory"), "normal", (True, True, False)),
    ("T1", MEETING, "revoked", (True, True, False)),
    ("T4", send(), "repeated", (True, True, False)),
])
def test_approved_comparison_cases(lab, runtime, mode, task, raw, condition, expected):
    case = lab(mode, task, fixture=Fixture.SUMMARY_SEEDED)
    if condition == "revoked":
        runtime.delegations.revoke(case.context.delegation_id)
    if condition == "repeated":
        assert case.call(send()).execution is Execution.SUCCEEDED
    before = case.sandbox.snapshot()
    prior_dispatches = len(case.invocations)

    result = case.call(raw)
    allowed = expected[list(PolicyMode).index(mode)]
    assert result.decision.allowed is result.dispatched is allowed
    assert len(case.invocations) - prior_dispatches == int(allowed)
    if allowed:
        assert result.execution is Execution.SUCCEEDED
    else:
        assert case.sandbox.snapshot() == before
        assert result.model_response() == {"status": "denied"} and result.data is None


@pytest.mark.parametrize("mode", list(PolicyMode))
@pytest.mark.parametrize(("task", "fixture", "calls", "scoped_status"), [
    ("T1", Fixture.SUMMARY_ABSENT, (MEETING,), DelegationStatus.ACTIVE),
    ("T2", Fixture.SUMMARY_ABSENT, (request("read_document", "financial_report.txt"),), DelegationStatus.ACTIVE),
    ("T3", Fixture.SUMMARY_ABSENT, (MEETING, request("create_document", "summary.txt", content=EXPECTED_SUMMARY)),
     DelegationStatus.COMPLETED),
    ("T4", Fixture.SUMMARY_ABSENT, (request("read_email", "email_inbox"), send()), DelegationStatus.COMPLETED),
    ("T5", Fixture.SUMMARY_SEEDED, (request("delete_document", "summary.txt"),), DelegationStatus.COMPLETED),
    ("T6", Fixture.SUMMARY_ABSENT, (request("search_documents", "meeting_notes.txt", query="agenda"),
                                   request("search_documents", "meeting_notes.txt", query="Room")), DelegationStatus.ACTIVE),
])
def test_legitimate_tasks_dispatch_and_scoped_completion_tracks_effects(lab, runtime, mode, task, fixture, calls, scoped_status):
    case = lab(mode, task, fixture=fixture)
    received = [case.call(raw) for raw in calls]
    assert all(result.execution is Execution.SUCCEEDED for result in received)
    terminal = scoped_status if mode is PolicyMode.C else DelegationStatus.ACTIVE
    assert runtime.delegations.lookup(case.context.delegation_id).status is terminal
    if task == "T3":
        assert case.sandbox.read_document("summary.txt") == EXPECTED_SUMMARY
    if task == "T4":
        assert len(case.sandbox.snapshot().outbox) == 1
        assert received[-1].model_response() == {"status": "ok", "data": {"message_id": 1}}
    if task == "T5":
        assert case.sandbox.snapshot().documents["summary.txt"] is None
    if task == "T6":
        assert received[0].data == (AGENDA_LINE,)
        assert received[1].data == ("The next trial takes place in Room V-4.",)


@pytest.mark.parametrize("mode", [PolicyMode.A, PolicyMode.B])
def test_baselines_preserve_shared_run_without_task_authority_or_principal_grants(lab, runtime, mode):
    case = lab(mode, "T4")
    runtime.delegations.complete(case.context.delegation_id, successful_effect=next(
        grant.permission for grant in case.active.grants if grant.permission.action == "send"
    ))
    runtime.identities.replace_grants(PrincipalKind.HUMAN, "alice", frozenset())
    runtime.identities.replace_grants(PrincipalKind.AGENT, "email-agent", frozenset())
    assert case.gateway.handle(send(REVIEW), case.run).execution is Execution.SUCCEEDED
    assert case.gateway.handle(send(REVIEW), case.run).execution is Execution.SUCCEEDED
    assert len(case.sandbox.snapshot().outbox) == 2
    assert not any("delegation_id" in event for event in case.events)


def test_exact_canonical_object_is_reused_even_if_the_caller_mutates_the_payload(lab, monkeypatch):
    raw = request("create_document", "summary.txt", content="Original synthetic text")
    evaluated = []
    actual_evaluate = service.evaluate

    def evaluate(mode, invocation, *args):
        evaluated.append(invocation)
        return actual_evaluate(mode, invocation, *args)

    def audit(event):
        if event["event"] == "preliminary":
            raw["tool"] = "edit_document"
            raw["arguments"].update(resource_id="meeting_notes.txt", content="Replacement")

    monkeypatch.setattr(service, "evaluate", evaluate)
    case = lab(PolicyMode.C, "T3", audit_hook=audit)
    notes = case.sandbox.read_document("meeting_notes.txt")
    result = case.call(raw)
    assert result.execution is Execution.SUCCEEDED
    assert len(case.invocations) == 1 and len(evaluated) == 3
    assert all(call is case.invocations[0] for call in evaluated)
    assert case.sandbox.read_document("summary.txt") == "Original synthetic text"
    assert case.sandbox.read_document("meeting_notes.txt") == notes


def test_allowed_reads_and_search_return_only_targeted_data(lab):
    case = lab(PolicyMode.C, "T6")
    before = case.sandbox.snapshot()
    assert case.call(MEETING).data == before.documents["meeting_notes.txt"]
    assert case.call(request("search_documents", "meeting_notes.txt", query="2400 lab credits")).data == ()
    assert case.sandbox.snapshot() == before


@pytest.mark.parametrize("layer", [0, 1, 2])
def test_pdp_requires_read_in_each_layer_for_search(lab, runtime, layer):
    case = lab(PolicyMode.C, "T6")
    records = [runtime.identities.lookup(PrincipalKind.HUMAN, "alice"),
               runtime.identities.lookup(PrincipalKind.AGENT, "document-agent"), case.active]
    record = records[layer]
    records[layer] = replace(record, grants=frozenset(
        grant for grant in record.grants if grant.permission.action is not Action.READ
    ))
    invocation = canonicalise(request("search_documents", "meeting_notes.txt", query="agenda"))
    assert evaluate(PolicyMode.C, invocation, *records).reason is Reason.READ_REQUIRED
    assert not case.invocations


def test_executor_precondition_failure_is_an_admitted_dispatch_and_leaves_task_active(lab, runtime):
    case = lab(PolicyMode.C, "T3", fixture=Fixture.SUMMARY_SEEDED)
    before = case.sandbox.snapshot()
    result = case.call(request("create_document", "summary.txt", content="Additional content"))
    assert result.decision.allowed and result.dispatched and result.execution is Execution.FAILED
    assert result.execution_reason == "DOCUMENT_EXISTS"
    assert result.model_response() == {"status": "error"}
    assert case.sandbox.snapshot() == before
    assert runtime.delegations.lookup(case.context.delegation_id).status is DelegationStatus.ACTIVE


@pytest.mark.parametrize("mode", list(PolicyMode))
@pytest.mark.parametrize("invalid", ["run", "human", "agent", "session"])
def test_shared_binding_checks_apply_in_every_mode(lab, runtime, mode, invalid):
    case = lab(mode)
    run = case.run
    if invalid == "run":
        run = replace(run, run_id="unregistered-run")
    elif invalid == "human":
        runtime.identities.disable(PrincipalKind.HUMAN, "alice")
    elif invalid == "agent":
        runtime.identities.disable(PrincipalKind.AGENT, "document-agent")
    else:
        runtime.sessions.invalidate(case.token)
    result = case.gateway.handle(MEETING, run, case.context)
    assert result.decision.reason is Reason.INVALID_CONTEXT and not case.invocations
    assert "unregistered-run" not in repr(case.events)


def test_scoped_context_must_be_live_registered_and_from_the_exact_run(lab, runtime):
    case = lab(PolicyMode.C)
    another_run = runtime.sessions.start_run(case.token, "document-agent")
    for run, context in ((case.run, None), (case.run, replace(case.context)),
                         (another_run, case.context), (replace(case.run), case.context)):
        assert case.gateway.handle(MEETING, run, context).decision.reason is Reason.INVALID_CONTEXT
    principal = runtime.identities.lookup(PrincipalKind.HUMAN, "alice")
    runtime.identities.replace_grants(PrincipalKind.HUMAN, "alice", principal.grants)
    assert case.call(MEETING).decision.reason is Reason.STALE_RECORD and not case.invocations


@pytest.mark.parametrize("change", ["revoke", "expire", "reduce", "disable", "invalidate"])
def test_final_admission_rechecks_authority_after_persisting_intent(lab, runtime, change):
    def audit(event):
        if event["event"] != "dispatch_intent":
            return
        assert event["provisional"]
        if change == "revoke":
            runtime.delegations.revoke(case.context.delegation_id)
        elif change == "expire":
            runtime.clock.value = case.active.expires_at
        elif change == "reduce":
            runtime.identities.replace_grants(PrincipalKind.AGENT, "document-agent", frozenset())
        elif change == "disable":
            runtime.identities.disable(PrincipalKind.HUMAN, "alice")
        else:
            runtime.sessions.invalidate(case.token)

    case = lab(PolicyMode.C, "T3", audit_hook=audit)
    before = case.sandbox.snapshot()
    result = case.call(request("create_document", "summary.txt", content="Blocked change"))
    reasons = {"revoke": Reason.DELEGATION_REVOKED, "expire": Reason.DELEGATION_EXPIRED,
               "reduce": Reason.TASK_GRANTS_CHANGED, "disable": Reason.INVALID_CONTEXT, "invalidate": Reason.INVALID_CONTEXT}
    assert result.decision.reason is reasons[change]
    assert not result.dispatched and not case.invocations and case.sandbox.snapshot() == before
    confirmed = case.events[-1]
    assert confirmed["event"] == "admission" and confirmed["allowed"] is False
    assert confirmed["request_id"] == result.request_id


def test_revocation_between_preliminary_allow_and_intent_prevents_dispatch(lab, runtime):
    def audit(event):
        if event["event"] == "preliminary":
            runtime.delegations.revoke(case.context.delegation_id)

    case = lab(PolicyMode.C, audit_hook=audit)
    result = case.call(MEETING)
    assert result.decision.reason is Reason.DELEGATION_REVOKED and not case.invocations
    assert [event["event"] for event in case.events] == ["attempt", "validation", "preliminary", "admission"]


@pytest.mark.parametrize("mode", [PolicyMode.A, PolicyMode.B])
def test_baselines_also_recheck_shared_session_after_intent(lab, runtime, mode):
    def audit(event):
        if event["event"] == "dispatch_intent":
            runtime.sessions.invalidate(case.token)

    case = lab(mode, audit_hook=audit)
    result = case.gateway.handle(MEETING, case.run)
    assert result.decision.reason is Reason.INVALID_CONTEXT and not case.invocations


def test_known_send_failure_releases_reservation_and_reentrant_call_is_refused(lab, runtime):
    nested = []

    def handler(invocation, execute):
        nested.append(case.call(send()))
        if len(nested) == 1:
            raise SandboxError(ErrorCode.INVALID_ARGUMENT)
        return execute(invocation)

    case = lab(PolicyMode.C, "T4", executor_hook=handler)
    assert case.call(send()).execution is Execution.FAILED
    assert case.sandbox.snapshot().outbox == ()
    assert runtime.delegations.lookup(case.context.delegation_id).status is DelegationStatus.ACTIVE
    assert case.call(send()).execution is Execution.SUCCEEDED
    assert all(result.decision.reason is Reason.RUNTIME_UNAVAILABLE and not result.dispatched for result in nested)
    assert not case.call(send()).decision.allowed and len(case.sandbox.snapshot().outbox) == 1


@pytest.mark.parametrize("mode", list(PolicyMode))
def test_uncertain_send_quarantines_outbox_and_prevents_duplicates(lab, mode):
    def handler(invocation, execute):
        execute(invocation)
        raise RuntimeError("Private executor message")

    case = lab(mode, "T4", executor_hook=handler)
    first = case.call(send())
    assert first.decision.allowed and first.execution is Execution.UNKNOWN
    assert first.lifecycle == "quarantined" and first.model_response() == {"status": "error"}
    followup = case.call(send())
    assert followup.decision.reason is Reason.MUTATION_UNCERTAIN and not followup.dispatched
    assert len(case.sandbox.snapshot().outbox) == len(case.invocations) == 1
    assert "Private executor message" not in repr(case.events)


def test_interrupted_mutation_is_unconfirmed_and_blocks_a_later_retry(lab):
    def handler(invocation, execute):
        execute(invocation)
        raise KeyboardInterrupt

    case = lab(PolicyMode.A, "T4", executor_hook=handler)
    with pytest.raises(KeyboardInterrupt):
        case.call(send())
    assert case.events[-1]["event"] == "dispatch_intent"
    assert case.call(send()).decision.reason is Reason.MUTATION_UNCERTAIN
    assert len(case.sandbox.snapshot().outbox) == 1


def test_expiry_after_admitted_send_preserves_the_known_effect(lab, runtime):
    def handler(invocation, execute):
        result = execute(invocation)
        runtime.clock.value = case.active.expires_at
        return result

    case = lab(PolicyMode.C, "T4", executor_hook=handler)
    result = case.call(send())
    assert result.execution is Execution.SUCCEEDED and result.lifecycle == "expired_after_effect"
    assert runtime.delegations.lookup(case.context.delegation_id).status is DelegationStatus.EXPIRED
    assert not case.call(send()).dispatched and len(case.sandbox.snapshot().outbox) == 1


@pytest.mark.parametrize("stage", ["attempt", "validation", "preliminary", "dispatch_intent"])
def test_pre_dispatch_logging_failure_fails_closed(lab, stage):
    def audit(event):
        if event["event"] == stage:
            raise OSError("Private path")

    case = lab(PolicyMode.C, "T4", audit_hook=audit)
    result = case.call(send())
    assert result.decision.reason is Reason.AUDIT_UNAVAILABLE
    assert result.failed_audit_events == (stage,) and not result.dispatched
    assert not case.invocations and case.sandbox.snapshot().outbox == ()
    assert "Private path" not in repr(case.events)
    assert case.events[-1]["event"] == "admission" and not case.events[-1]["allowed"]


def test_outcome_logging_failure_preserves_success_and_consumed_authority(lab, runtime):
    def audit(event):
        if event["event"] == "outcome":
            raise OSError("Private path")

    case = lab(PolicyMode.C, "T4", audit_hook=audit)
    result = case.call(send())
    assert result.execution is Execution.SUCCEEDED and result.failed_audit_events == ("outcome",)
    assert runtime.delegations.lookup(case.context.delegation_id).status is DelegationStatus.COMPLETED
    assert not case.call(send()).dispatched and len(case.sandbox.snapshot().outbox) == 1


def test_unavailable_durable_destination_returns_observable_denial(lab, tmp_path):
    path = tmp_path / "missing-parent" / "journal.jsonl"
    case = lab(PolicyMode.C, audit_hook=JsonlAudit(path))
    result = case.call(MEETING)
    assert not result.dispatched and result.decision.reason is Reason.AUDIT_UNAVAILABLE
    assert result.failed_audit_events == ("attempt", "admission") and not path.exists()


def test_durable_journal_correlates_safe_metadata_without_unchecked_inputs(lab, tmp_path):
    path = tmp_path / "journal.jsonl"
    case = lab(PolicyMode.C, "T4", audit_hook=JsonlAudit(path))
    other = lab(PolicyMode.C, "T1", audit_hook=JsonlAudit(tmp_path / "independent.jsonl"))
    malformed = case.call({"tool": "read_document", "session_token": case.token,
                           "arguments": {"resource_id": "malformed-resource-marker"}})
    policy_denied = case.call(send(REVIEW))
    result = case.call(send())
    other_result = other.call(MEETING)
    assert len({entry.request_id for entry in (malformed, policy_denied, result, other_result)}) == 4
    raw = path.read_text(encoding="utf-8")
    assert all(value not in raw for value in (case.token, case.proof, "malformed-resource-marker",
                                               "Synthetic subject marker", "Synthetic body marker"))
    assert "session_token" not in raw
    events = [json.loads(line) for line in raw.splitlines()]
    by_request = {request_id: [item for item in events if item["request_id"] == request_id]
                  for request_id in (malformed.request_id, policy_denied.request_id, result.request_id)}
    assert all(event["run_id"] == case.run.run_id for event in events)
    assert all("resource_id" not in event and "destination" not in event for event in by_request[malformed.request_id])
    assert by_request[policy_denied.request_id][-1]["destination"] == REVIEW
    assert by_request[policy_denied.request_id][-1]["reason"] == "DESTINATION_DENIED"
    successful = by_request[result.request_id]
    assert [event["event"] for event in successful] == [
        "attempt", "validation", "preliminary", "dispatch_intent", "admission", "dispatch", "outcome", "lifecycle",
    ]
    assert successful[3]["provisional"] and successful[5]["dispatched"]
    assert successful[4]["delegation_version"] == case.active.version
    assert other_result.request_id not in raw


def test_journal_omits_query_and_document_text_even_on_success(lab, tmp_path):
    query = "Synthetic query marker"
    path = tmp_path / "search.jsonl"
    case = lab(PolicyMode.C, "T6", audit_hook=JsonlAudit(path))
    document = case.call(MEETING).data
    assert case.call(request("search_documents", "meeting_notes.txt", query=query)).execution is Execution.SUCCEEDED
    raw = path.read_text(encoding="utf-8")
    assert query not in raw and document.splitlines()[0] not in raw


def test_timing_boundaries_separate_audit_policy_and_execution(lab, monkeypatch):
    now = 0
    real_validate, real_evaluate = service.canonicalise, service.evaluate

    def validate(raw):
        nonlocal now
        now += 3
        return real_validate(raw)

    def evaluate(*args):
        nonlocal now
        now += 5
        return real_evaluate(*args)

    def audit(event):
        nonlocal now
        now += 13

    def handler(invocation, execute):
        nonlocal now
        now += 7
        return execute(invocation)

    monkeypatch.setattr(service, "canonicalise", validate)
    monkeypatch.setattr(service, "evaluate", evaluate)
    case = lab(PolicyMode.C, audit_hook=audit, executor_hook=handler, monotonic=lambda: now)
    timing = case.call(MEETING).timing
    assert (timing.policy_ns, timing.enforcement_ns, timing.executor_ns, timing.gateway_overhead_ns) == (8, 70, 7, 109)
    assert len(timing.audit_writes_ns) == 7
    assert all(duration == 13 for _, duration in timing.audit_writes_ns)
