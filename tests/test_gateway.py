from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from agent_authz.audit.completeness import Issue, Status, assess_journal
from agent_authz.audit.observations import AttemptObservation, BindingObservation, OperationObservation, OutcomeObservation
from agent_authz.audit.reader import read_journal
from agent_authz.delegation import DelegationStatus
from agent_authz.gateway import Execution, Gateway, PolicyMode
from agent_authz.gateway import service
from agent_authz.gateway.audit import JsonlAudit
from agent_authz.gateway.executor import _Executor
from agent_authz.gateway.models import Reason, RecordVersions
from agent_authz.gateway.policies import evaluate
from agent_authz.gateway.registry import ValidationError, canonicalise
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

    def authority_records():
        runtime.sessions.validate_run(case.run)
        session = runtime.sessions.validate_session(case.token)
        human = runtime.identities.lookup(PrincipalKind.HUMAN, case.run.human_id)
        agent = runtime.identities.lookup(PrincipalKind.AGENT, case.run.agent_id)
        delegation = runtime.delegations.lookup(case.context.delegation_id)
        assert case.context.run is delegation.run is case.run
        assert session.human_id == case.run.human_id and delegation.task_id == case.context.task_id == task
        return session, human, agent, delegation

    before = case.sandbox.snapshot()
    before_authority = authority_records()
    prior_dispatches = len(case.invocations)

    result = case.call(raw)
    after = case.sandbox.snapshot()
    after_authority = authority_records()
    allowed = expected[list(PolicyMode).index(mode)]
    assert result.decision.allowed is result.dispatched is allowed
    assert len(case.invocations) - prior_dispatches == int(allowed)
    audit = [event for event in case.events if event["request_id"] == result.request_id]
    admission, = (event for event in audit if event["event"] == "admission")
    assert admission["allowed"] is allowed
    if not allowed:
        assert result.execution is Execution.NOT_DISPATCHED
        assert admission["dispatched"] is False
        assert not any(event["event"] in {"dispatch_intent", "dispatch", "outcome"} for event in audit)
        assert after == before and after_authority == before_authority
        assert result.model_response() == {"status": "denied"} and result.data is None
        return

    assert result.execution is Execution.SUCCEEDED
    assert after_authority[:3] == before_authority[:3]
    arguments = raw["arguments"]
    target = arguments["resource_id"]
    tool = raw["tool"]
    if tool == "read_document":
        assert after == before and result.data == before.documents[target]
    elif tool == "search_documents":
        matches = tuple(line for line in before.documents[target].splitlines() if arguments["query"] in line)
        assert after == before and result.data == matches and matches
    elif tool == "send_simulated_email":
        message = after.outbox[-1]
        assert after == replace(before, outbox=(*before.outbox, message))
        assert (message.destination, message.subject, message.body) == (
            arguments["destination"], arguments["subject"], arguments["body"],
        )
    else:
        assert tool in {"edit_document", "delete_document"}
        replacement = arguments.get("content")
        assert before.documents[target] != replacement
        assert after == replace(before, documents={**before.documents, target: replacement})


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


def observe_audit_call(case, runtime, raw, *, registered=True, mode=PolicyMode.C):
    run, context = case.run, case.context
    binding = BindingObservation(run.run_id, run.session_id, run.human_id, run.agent_id,
                                 context.task_id, context.delegation_id) if registered else None
    try:
        operation = OperationObservation.from_invocation(canonicalise(raw))
    except ValidationError:
        operation = None

    def versions():
        return RecordVersions(
            runtime.identities.lookup(PrincipalKind.HUMAN, run.human_id).version,
            runtime.identities.lookup(PrincipalKind.AGENT, run.agent_id).version,
            runtime.delegations.lookup(context.delegation_id).version,
        )

    before = versions() if registered else None
    result = case.call(raw) if registered else case.gateway.handle(raw, replace(run), context)
    return result, AttemptObservation(
        run.run_id if registered else None, 1, mode, result.request_id, binding, operation is not None,
        operation, OutcomeObservation.from_result(result), before, versions() if registered else None,
    )


@pytest.mark.parametrize(("rejection", "sequence"), [
    ("structure", ("attempt", "validation", "admission")),
    ("policy", ("attempt", "validation", "preliminary", "admission")),
    ("binding", ("attempt", "validation", "preliminary", "admission")),
])
def test_persisted_rejection_paths_have_no_effect_or_fabricated_binding(lab, runtime, tmp_path, rejection, sequence):
    path = tmp_path / "journal.jsonl"
    case = lab(PolicyMode.C, audit_hook=JsonlAudit(path))
    raw = {"fixture_marker": "neutral malformed value"} if rejection == "structure" else request(
        "read_document", "public_report.txt"
    )
    before = case.sandbox.snapshot()
    result, observed = observe_audit_call(case, runtime, raw, registered=rejection != "binding")
    audit = assess_journal(read_journal(path), [observed])
    assert audit.globally_clean and audit.attempts[0].required_events == sequence
    assert not result.dispatched and not case.invocations and case.sandbox.snapshot() == before
    assert result.model_response() == {"status": "denied"} and result.data is None
    if rejection == "structure":
        assert all("tool" not in row.fields for row in audit.journal.records)
    if rejection == "binding":
        assert all("run_id" not in row.fields and "session_id" not in row.fields for row in audit.journal.records)
    contradictory = assess_journal(audit.journal, [replace(observed, effect="observed_success")])
    assert contradictory.attempts[0].status is Status.INCONSISTENT
    assert Issue.EFFECT_CONFLICT.value in contradictory.issue_counts


@pytest.mark.parametrize("trigger", ["preliminary", "dispatch_intent"])
def test_persisted_late_denial_accepts_legitimate_version_change(lab, runtime, tmp_path, trigger):
    path = tmp_path / "journal.jsonl"
    write = JsonlAudit(path)

    def audit_hook(event):
        write(event)
        if event["event"] == trigger:
            runtime.delegations.revoke(case.context.delegation_id)

    case = lab(PolicyMode.C, audit_hook=audit_hook)
    result, observed = observe_audit_call(case, runtime, MEETING)
    assert not result.dispatched and not case.invocations
    assert result.decision.reason is Reason.DELEGATION_REVOKED
    runtime.sessions.validate_run(case.run)
    audit = assess_journal(read_journal(path), [observed])
    assert audit.globally_clean
    records = audit.attempts[0].records
    assert ("dispatch_intent" in [row.event for row in records]) is (trigger == "dispatch_intent")
    assert records[2].fields["delegation_version"] < records[-1].fields["delegation_version"]


@pytest.mark.parametrize("stage", ["attempt", "validation", "preliminary", "dispatch_intent"])
def test_persisted_pre_dispatch_fault_cannot_execute(lab, runtime, tmp_path, stage):
    path = tmp_path / "journal.jsonl"
    write = JsonlAudit(path)

    def audit_hook(event):
        if event["event"] == stage:
            raise OSError("private test exception")
        write(event)

    case = lab(PolicyMode.C, audit_hook=audit_hook)
    before = case.sandbox.snapshot()
    result, observation = observe_audit_call(case, runtime, MEETING)
    assert result.decision.reason is Reason.AUDIT_UNAVAILABLE and not result.dispatched
    assert not case.invocations and case.sandbox.snapshot() == before
    audit = assess_journal(read_journal(path), [observation])
    assert audit.attempts[0].status is Status.INCOMPLETE
    assert audit.issue_counts == {"unconfirmed_write": 1, "missing_event": 1}
    assert audit.journal.records[-1].event == "admission"


@pytest.mark.parametrize("write_before_failure", [False, True])
def test_post_dispatch_failure_preserves_effect_and_unconfirmed_persistence(lab, runtime, tmp_path, write_before_failure):
    path = tmp_path / "journal.jsonl"
    write = JsonlAudit(path)

    def audit_hook(event):
        if event["event"] == "outcome":
            if write_before_failure:
                write(event)
            raise OSError("private persistence marker")
        write(event)

    case = lab(PolicyMode.C, "T4", audit_hook=audit_hook)
    result, observation = observe_audit_call(case, runtime, send())
    assert result.execution is Execution.SUCCEEDED and len(case.sandbox.snapshot().outbox) == 1
    audit = assess_journal(read_journal(path), [observation])
    assert audit.attempts[0].status is Status.INCOMPLETE
    assert audit.issue_counts[Issue.UNCONFIRMED_WRITE.value] == 1
    assert (Issue.MISSING_EVENT.value in audit.issue_counts) is not write_before_failure
    assert "private persistence marker" not in path.read_text(encoding="utf-8") + repr(audit.issue_counts)


@pytest.mark.parametrize(("failure", "execution", "lifecycle"), [
    (SandboxError(ErrorCode.INVALID_ARGUMENT), Execution.FAILED, "failure_no_effect"),
    (RuntimeError("private executor sentinel"), Execution.UNKNOWN, "quarantined"),
])
def test_complete_audit_can_describe_failed_or_uncertain_execution(lab, runtime, tmp_path, failure, execution, lifecycle):
    path = tmp_path / "journal.jsonl"

    def handler(invocation, execute):
        raise failure

    case = lab(PolicyMode.C, "T4", audit_hook=JsonlAudit(path), executor_hook=handler)
    result, observation = observe_audit_call(case, runtime, send())
    assert result.dispatched and result.execution is execution and result.lifecycle == lifecycle
    audit = assess_journal(read_journal(path), [observation])
    assert audit.globally_clean and audit.attempts[0].observation.effect is None
    assert "private executor sentinel" not in path.read_text(encoding="utf-8")


def test_versioned_journal_and_diagnostics_exclude_synthetic_content_and_credentials(lab, runtime, tmp_path):
    path = tmp_path / "journal.jsonl"
    write = JsonlAudit(path)
    query, document = "query sentinel", "document sentinel"
    subject, body, malformed = "subject sentinel", "body sentinel", "malformed sentinel"
    replacement = "replacement sentinel"
    reader = lab(PolicyMode.C, "T6", audit_hook=write)
    reader.sandbox.edit_document("meeting_notes.txt", f"{query} {document}")
    assert reader.call(request("search_documents", "meeting_notes.txt", query=query)).data
    editor = lab(PolicyMode.C, "T3", audit_hook=write)
    assert editor.call(request("create_document", "summary.txt", content=replacement)).execution is Execution.SUCCEEDED
    sender = lab(PolicyMode.C, "T4", audit_hook=write)
    assert sender.call(request("send_simulated_email", "email_outbox", destination=TEAM,
                               subject=subject, body=body)).dispatched
    rejected = sender.call({"fixture_content": malformed, "bearer": sender.token})
    assert not rejected.dispatched and rejected.model_response() == {"status": "denied"}
    raw_text = path.read_text(encoding="utf-8")
    journal = read_journal(path)
    assert not journal.problems and all(row.fields["schema_version"] == 1 for row in journal.records)
    assert all(value not in raw_text + repr(journal.problems)
               for value in (query, document, subject, body, malformed, replacement))
    # The clock fixture numbers IDs, so one complete ID can prefix another.
    assert all(json.dumps(value) not in raw_text for actor in (reader, editor, sender) for value in (actor.token, actor.proof))
    assert any(row.fields.get("destination") == TEAM for row in journal.records)
