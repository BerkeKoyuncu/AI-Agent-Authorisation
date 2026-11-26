"""Review predicates tested with normal runs and passive copies of observations."""

import json
from dataclasses import replace

import pytest

from agent_authz.agent.models import Method, Role, Termination
from agent_authz.delegation import DelegationStatus
from agent_authz.gateway import Execution, PolicyMode
from agent_authz.gateway.registry import TOOL_REGISTRY, canonicalise
from agent_authz.sandbox.catalogue import RESOURCE_CATALOGUE
from agent_authz.sandbox.fixtures import AGENDA_QUERY, INBOX_DRAFT
from agent_authz.scenarios import runner
from agent_authz.scenarios.authority import Authority, Evidence, Label, Lifecycle
from agent_authz.scenarios.catalogue import CASES, PERMISSION_INVENTORY
from agent_authz.scenarios.objectives import assess_review_objective
from agent_authz.scenarios.runner import _completion, _replay_conformance, run_scenario


_OUTSIDE = Label(Authority.UNAUTHORISED, "reviewed out-of-scope observation")


def test_normal_replays_freeze_and_execute_the_exact_manifest_requests():
    for case in CASES.values():
        if not case.methods:
            assert not case.replay_json
            continue
        invocations = [canonicalise(json.loads(raw)) for raw in case.replay_json]
        assert [(item.tool, item.resource_id) for item in invocations] == list(case.required_operations)
        result = run_scenario(case.case_id, PolicyMode.C)
        assert result.replay_conformance is Evidence.SUCCESS
        assert [attempt.gateway_input_json for attempt in result.attempts] == list(case.replay_json)


@pytest.mark.parametrize("slot", PERMISSION_INVENTORY, ids=[
    f"{slot.action}-{slot.resource_id}" + (f"-{slot.destination}" if slot.destination else "")
    for slot in PERMISSION_INVENTORY
])
def test_permission_candidate_is_canonicalised_without_dispatching(slot):
    kind = RESOURCE_CATALOGUE[slot.resource_id].kind
    matches = [(tool, spec) for tool, spec in TOOL_REGISTRY.items()
               if spec.kind is kind and spec.action == slot.action]
    (tool, spec), = matches
    assert ("destination" in {arg.name for arg in spec.arguments}) == (slot.destination is not None)

    arguments = {"resource_id": slot.resource_id}
    if slot.action == "search":
        arguments["query"] = AGENDA_QUERY if slot.resource_id == "meeting_notes.txt" else "synthetic"
    elif slot.action in {"create", "edit"}:
        arguments["content"] = "Synthetic schema validation text."
    elif slot.action == "send":
        arguments.update(destination=slot.destination, subject=INBOX_DRAFT.subject, body=INBOX_DRAFT.body)

    candidate = canonicalise({"tool": tool, "arguments": arguments})
    assert (candidate.tool, candidate.action, candidate.resource_id) == (tool, slot.action, slot.resource_id)
    assert dict(candidate.arguments) == arguments


def test_completion_and_conformance_are_independent_of_an_extra_denial():
    result = run_scenario("N3", PolicyMode.C)
    source, create = result.attempts
    # Add a passive observation, without dispatching a second proposal.
    extra = replace(source, sequence=2, gateway_input_json=None, invocation=None, authority=_OUTSIDE,
                    dispatched=False, execution=Execution.NOT_DISPATCHED, effect=Evidence.ABSENT)
    attempts = source, extra, replace(create, sequence=3)
    assert _completion(result.case, Method.REPLAY, result.run, attempts, result.before, result.after) == (
        Evidence.SUCCESS, Evidence.SUCCESS,
    )
    assert _replay_conformance(result.case, Method.REPLAY, result.run, attempts) is Evidence.ABSENT
    reviewed = replace(result, attempts=attempts)
    assert reviewed.unauthorised_attempts == (extra,)
    assert not reviewed.verified_unauthorised_effects


def test_compatible_side_effect_does_not_erase_legitimate_completion():
    result = run_scenario("N3", PolicyMode.A, Method.STUB)
    unrelated = run_scenario("N2", PolicyMode.A).attempts[0]
    side_effect = replace(unrelated, sequence=3, authority=_OUTSIDE)
    attempts = (*result.attempts, side_effect)
    assert _completion(result.case, Method.STUB, result.run, attempts, result.before, result.after) == (
        Evidence.SUCCESS, Evidence.SUCCESS,
    )
    assert replace(result, attempts=attempts).verified_unauthorised_effects == (side_effect,)


def test_search_completion_requires_query_and_returned_agenda_line():
    result = run_scenario("N6", PolicyMode.C)
    attempt, = result.attempts
    alternative = canonicalise({"tool": "search_documents",
                                "arguments": {"resource_id": "meeting_notes.txt", "query": "lantern"}})
    assert _completion(result.case, Method.REPLAY, result.run, (replace(attempt, invocation=alternative),),
                       result.before, result.after) == (Evidence.ABSENT, Evidence.NOT_APPLICABLE)
    history = tuple(message for message in result.run.conversation if message.role is not Role.TOOL)
    assert _completion(result.case, Method.REPLAY, replace(result.run, conversation=history),
                       result.attempts, result.before, result.after) == (Evidence.ABSENT, Evidence.NOT_APPLICABLE)


@pytest.mark.parametrize("policy", tuple(PolicyMode))
def test_pre_attempt_shared_binding_and_independent_lifecycle(policy):
    result = run_scenario("N4", policy)
    for attempt in result.attempts:
        binding = attempt.before.authority
        assert binding.shared_valid
        assert binding.context.run.human_id == result.case.human_id == binding.human.principal_id
        assert binding.context.run.agent_id == result.case.agent_id == binding.agent.principal_id
        assert binding.context.task_id == result.case.task_id
        assert attempt.pre_attempt_lifecycle is Lifecycle.ACTIVE
        assert attempt.backend_receipt is Evidence.NOT_APPLICABLE
    assert result.task_lifecycle is Lifecycle.ENDED
    actual_status = result.attempts[-1].after.authority.delegation.status
    assert actual_status is (DelegationStatus.COMPLETED if policy is PolicyMode.C else DelegationStatus.ACTIVE)


def test_labeller_uses_observed_binding_even_if_verdict_is_allow(monkeypatch):
    prepare_task = runner.prepare_task

    def with_binding_observation(*args, **kwargs):
        prepared = prepare_task(*args, **kwargs)
        return replace(prepared, observe_authority=lambda: replace(prepared.observe_authority(), shared_valid=False))

    monkeypatch.setattr(runner, "prepare_task", with_binding_observation)
    result = run_scenario("N1", PolicyMode.A)
    attempt, = result.attempts
    assert result.run.termination is Termination.FINAL_RESPONSE
    assert attempt.final_allowed is True and attempt.authority.authority is Authority.UNAUTHORISED


def test_deletion_objective_uses_effect_and_requires_complete_absence_evidence():
    normal, = run_scenario("N5", PolicyMode.C).attempts
    observed = replace(normal, authority=_OUTSIDE)
    assert assess_review_objective("X5", observed, trace_complete=False).objective is Evidence.SUCCESS
    contradicts_effect = replace(observed, dispatched=False)
    assert assess_review_objective("X5", contradicts_effect, trace_complete=True).objective is Evidence.UNKNOWN
    denial = replace(observed, dispatched=False, execution=Execution.NOT_DISPATCHED, after=observed.before,
                     history_content='{"status":"denied"}', effect=Evidence.ABSENT)
    assert assess_review_objective("X5", denial, trace_complete=True).objective is Evidence.ABSENT
    assert assess_review_objective("X5", denial, trace_complete=False).objective is Evidence.UNKNOWN
    assert assess_review_objective("X5", replace(denial, after=None), trace_complete=True).objective is Evidence.UNKNOWN


def test_delegation_and_override_integrity_are_reviewed_against_trusted_records():
    normal, = run_scenario("N1", PolicyMode.C).attempts
    denial = replace(normal, invocation=None, authority=_OUTSIDE, execution=Execution.NOT_DISPATCHED,
                     dispatched=False, effect=Evidence.ABSENT, after=normal.before)
    for case_id in ("X6", "X7"):
        assert assess_review_objective(case_id, denial, trace_complete=True).objective is Evidence.ABSENT
        assert assess_review_objective(case_id, replace(denial, after=None),
                                       trace_complete=True).objective is Evidence.UNKNOWN
    before = denial.before.authority
    reduced = replace(before.human, grants=frozenset())
    after = replace(denial.after, authority=replace(before, human=reduced))
    assert assess_review_objective("X6", replace(denial, after=after),
                                   trace_complete=True).objective is Evidence.SUCCESS
    changed_task = replace(before.context, task_id="T6")
    after = replace(denial.after, authority=replace(before, context=changed_task))
    assert assess_review_objective("X7", replace(denial, after=after),
                                   trace_complete=True).objective is Evidence.SUCCESS
    dispatched = replace(denial, dispatched=True, execution=Execution.UNKNOWN)
    assert assess_review_objective("X7", dispatched, trace_complete=False).objective is Evidence.SUCCESS


def test_identity_and_resource_observations_are_separate():
    normal, = run_scenario("N1", PolicyMode.A).attempts
    observed_effect = replace(
        normal, authority=_OUTSIDE, invocation=replace(normal.invocation, resource_id="public_report.txt"),
        history_content=json.dumps({"status": "ok", "data": normal.before.sandbox.documents["public_report.txt"]}),
    )
    assessment = assess_review_objective("X14", observed_effect, trace_complete=True)
    assert assessment.objective is Evidence.ABSENT and assessment.additional_read_effect is Evidence.SUCCESS
    inconsistent = replace(observed_effect, in_history=Evidence.ABSENT)
    assert assess_review_objective("X14", inconsistent, trace_complete=True).additional_read_effect is Evidence.UNKNOWN


def test_semantic_review_uses_reference_text_and_actual_append():
    normal = run_scenario("N4", PolicyMode.C).attempts[-1]
    reference = "A neutral synthetic fixture variant."
    args = {**dict(normal.invocation.arguments), "body": reference}
    message, = normal.after.sandbox.outbox
    state = replace(normal.after.sandbox, outbox=(replace(message, body=reference),))
    observed = replace(normal, invocation=replace(normal.invocation, arguments=tuple(args.items())),
                       after=replace(normal.after, sandbox=state))
    assert assess_review_objective("X10", observed, trace_complete=True).objective is Evidence.UNKNOWN
    assert assess_review_objective("X10", observed, trace_complete=True,
                                   expected_text=reference).objective is Evidence.SUCCESS
    assert assess_review_objective("X10", replace(observed, after=normal.after), trace_complete=True,
                                   expected_text=reference).objective is Evidence.UNKNOWN


def test_lifecycle_review_uses_observed_revocation_and_shared_session():
    normal, = run_scenario("N1", PolicyMode.A).attempts
    observation = replace(normal, authority=_OUTSIDE, pre_attempt_lifecycle=Lifecycle.ENDED)
    assert assess_review_objective("X12", observation, trace_complete=True).objective is Evidence.UNKNOWN
    binding = observation.before.authority
    revoked = replace(binding.delegation, status=DelegationStatus.REVOKED)
    state = replace(observation.before, authority=replace(binding, delegation=revoked))
    assert assess_review_objective("X12", replace(observation, before=state, after=state),
                                   trace_complete=True).objective is Evidence.SUCCESS


def test_completion_keeps_exact_outbox_count_and_unrelated_resource_constraints():
    mail = run_scenario("N4", PolicyMode.C)
    history = tuple(message for message in mail.run.conversation if message.sequence != mail.attempts[0].sequence)
    assert _completion(mail.case, Method.REPLAY, replace(mail.run, conversation=history),
                       mail.attempts, mail.before, mail.after) == (Evidence.ABSENT, Evidence.ABSENT)
    extra = replace(mail.after.outbox[0], message_id=2)
    final = replace(mail.after, outbox=(*mail.after.outbox, extra))
    assert _completion(mail.case, Method.REPLAY, mail.run, mail.attempts, mail.before, final) == (
        Evidence.SUCCESS, Evidence.ABSENT,
    )
    deleted = run_scenario("N5", PolicyMode.C)
    final = replace(deleted.after, documents={**deleted.after.documents, "meeting_notes.txt": "Changed fixture."})
    assert _completion(deleted.case, Method.REPLAY, deleted.run, deleted.attempts, deleted.before, final) == (
        Evidence.SUCCESS, Evidence.ABSENT,
    )
