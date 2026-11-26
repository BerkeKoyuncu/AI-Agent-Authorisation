from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from agent_authz.agent.models import (
    AgentError, Backend, Issue, Method, ModelTurn, Role, RunLimits, Termination, ToolProposal, TurnStatus,
)
from agent_authz.agent.prompts import SYSTEM_PROMPT, TASK_PROMPTS, ReplayAdapter, StubAdapter, normal_replay
from agent_authz.agent.runtime import AgentRuntime, prepare_task
from agent_authz.gateway import Execution, Gateway, PolicyMode, tool_schemas
from agent_authz.gateway.executor import _Executor
from agent_authz.gateway.models import Reason
from agent_authz.sandbox import Fixture, SandboxEnvironment
from agent_authz.sandbox.fixtures import AGENDA_LINE, FINANCIAL_FACTS, INBOX_DRAFT, MEETING_FACTS
from agent_authz.tasks import TASK_CATALOGUE


def proposal(tool="read_document", resource_id="meeting_notes.txt", *, provider_id=None, **arguments):
    return ToolProposal({"tool": tool, "arguments": {"resource_id": resource_id, **arguments}}, provider_id)


def send():
    return proposal("send_simulated_email", "email_outbox", destination=INBOX_DRAFT.destination,
                    subject=INBOX_DRAFT.subject, body=INBOX_DRAFT.body)


class BackendDouble:
    def __init__(self, generate, method=Method.STUB):
        self.backend = Backend(method, "test-double")
        self.generate = generate


@pytest.fixture
def bind(runtime):
    def create(task_id="T1", mode=PolicyMode.C, *, limits=RunLimits(), clock=lambda: 0, executor_hook=None):
        task = TASK_CATALOGUE[task_id]
        token, run = runtime.start(task.human_id, task.agent_id)
        pending = runtime.delegations.issue(run, task_id)
        runtime.delegations.activate(run, pending.delegation_id)
        context = runtime.delegations.bind_context(run, pending.delegation_id)
        sandbox = SandboxEnvironment(Fixture.SUMMARY_SEEDED if task_id == "T5" else Fixture.SUMMARY_ABSENT)
        execute = _Executor(sandbox).execute
        events, effects, submissions = [], [], []

        def invoke(call):
            effects.append(call)
            return execute(call) if executor_hook is None else executor_hook(call, execute)

        class ObservedGateway(Gateway):
            def handle(self, request, bound_run, bound_context=None):
                submissions.append((request, bound_run, bound_context))
                return super().handle(request, bound_run, bound_context)

        gateway = ObservedGateway(mode, runtime.sessions, runtime.delegations, sandbox, events.append, executor=invoke)
        agent = AgentRuntime(task_id, runtime.sessions, gateway, run, context, limits=limits, clock=clock)
        return SimpleNamespace(agent=agent, sandbox=sandbox, run=run, context=context, token=token,
                               events=events, effects=effects, submissions=submissions)
    return create


@pytest.mark.parametrize("task_id", tuple(TASK_CATALOGUE))
def test_stub_supports_all_six_tasks_with_confirmed_results_and_fresh_fixture(task_id):
    task = prepare_task(task_id, PolicyMode.C, lambda event: None)
    initial = task.sandbox.snapshot()
    result = task.runtime.run(StubAdapter(task_id))
    assert result.termination is Termination.FINAL_RESPONSE
    assert result.backend.method is Method.STUB and all(turn.inference_ns is None for turn in result.turns)
    assert all(call.gateway.execution is Execution.SUCCEEDED for turn in result.turns for call in turn.calls)
    snapshot = task.sandbox.snapshot()
    if task_id == "T1":
        assert all(fact in result.final_response for fact in MEETING_FACTS)
    elif task_id == "T2":
        assert all(fact in result.final_response for fact in FINANCIAL_FACTS)
    elif task_id == "T3":
        assert all(fact in snapshot.documents["summary.txt"] for fact in MEETING_FACTS)
        assert result.final_response == "Created summary.txt from the meeting notes."
    elif task_id == "T4":
        (message,) = snapshot.outbox
        assert (message.destination, message.subject, message.body) == (INBOX_DRAFT.destination, INBOX_DRAFT.subject, INBOX_DRAFT.body)
        assert result.final_response == "Queued the simulated draft."
    elif task_id == "T5":
        assert initial.documents["summary.txt"] and snapshot.documents["summary.txt"] is None
        assert result.final_response == "Deleted the temporary summary.txt."
    elif task_id == "T6":
        assert result.final_response == AGENDA_LINE
    assert prepare_task(task_id, PolicyMode.C, lambda event: None).sandbox.snapshot() == initial


def test_stub_does_not_fabricate_a_summary_on_denial_or_failure(bind):
    denied = bind()
    initial = denied.sandbox.snapshot()
    denied_result = denied.agent.run(StubAdapter("T1", show_denial=True))
    assert not denied.effects and denied_result.termination is Termination.FINAL_RESPONSE
    denied_gateway = denied_result.turns[0].calls[0].gateway
    assert denied_gateway.decision.reason is Reason.OUTSIDE_TASK_SCOPE
    assert not denied_gateway.dispatched and denied_gateway.execution is Execution.NOT_DISPATCHED
    assert denied.sandbox.snapshot() == initial
    assert denied_result.turns[0].calls[0].model_result_json == '{"status":"denied"}'
    tool_message, = (message for message in denied_result.conversation if message.role is Role.TOOL)
    assert json.loads(tool_message.content) == {"status": "denied"}
    assert "could not complete" in denied_result.final_response
    absent = bind()
    absent.sandbox.delete_document("meeting_notes.txt")
    failed = absent.agent.run(StubAdapter("T1"))
    assert failed.turns[0].calls[0].gateway.execution is Execution.FAILED
    assert "could not complete" in failed.final_response


def test_stub_and_replay_are_offline_and_replay_does_not_branch_on_denial(bind, monkeypatch):
    def no_network(*args, **kwargs):
        pytest.fail("Offline methods must not connect to any host")

    monkeypatch.setattr("socket.create_connection", no_network)
    assert bind().agent.run(StubAdapter("T1")).termination is Termination.FINAL_RESPONSE
    first = proposal("read_document", "public_report.txt")
    replay = ReplayAdapter(((first,), (proposal(),)))
    first.envelope["tool"] = "changed"
    case = bind()
    result = case.agent.run(replay)
    assert result.backend.method is Method.REPLAY and all(turn.inference_ns is None for turn in result.turns)
    assert [turn.calls[0].gateway.decision.allowed for turn in result.turns[:2]] == [False, True]
    assert [call[0]["arguments"]["resource_id"] for call in case.submissions] == ["public_report.txt", "meeting_notes.txt"]
    assert bind().agent.run(normal_replay("T1")).final_response == "Replay sequence finished."
    with pytest.raises(AgentError):
        case.agent.run(replay)


def test_model_visible_prompts_schemas_settings_and_timeout_are_identical_and_detached(bind):
    observed = []
    for mode in PolicyMode:
        case = bind(mode=mode)

        def inspect(messages, schemas, settings, *, timeout, max_response_bytes):
            observed.append(([(m.role, m.content) for m in messages], list(schemas), settings, timeout, max_response_bytes))
            object.__setattr__(messages[0], "content", "changed copy")
            schemas.clear()
            return ModelTurn(proposals=(proposal(),)) if len(messages) == 2 else ModelTurn("Finished.")

        result = case.agent.run(BackendDouble(inspect))
        assert result.conversation[0].content != "changed copy"
        assert len(case.submissions) == 1 and case.submissions[0][1:] == (case.run, case.context)
        assert len(result.conversation) == 5
    assert observed[:2] == observed[2:4] == observed[4:]
    assert all(config[1] == tool_schemas() and config[3] == 60 for config in observed)
    assert not any("policy" in repr(config).lower() for config in observed)


def test_batch_correlation_uses_local_order_even_with_duplicate_provider_ids(bind):
    case = bind(mode=PolicyMode.A)
    batch = (
        proposal("read_document", "meeting_notes.txt", provider_id="same-id"),
        proposal("read_document", "public_report.txt", provider_id="same-id"),
    )
    result = case.agent.run(ReplayAdapter((batch,)))
    assert [call.provider_id for call in result.turns[0].calls] == ["same-id", "same-id"]
    assert [item.resource_id for item in case.effects] == ["meeting_notes.txt", "public_report.txt"]
    tool_messages = [message for message in result.conversation if message.role is Role.TOOL]
    assert [message.sequence for message in tool_messages] == [1, 2]
    assert [json.loads(message.content)["data"] for message in tool_messages] == [
        case.sandbox.read_document("meeting_notes.txt"), case.sandbox.read_document("public_report.txt"),
    ]


def test_tool_result_instructions_stay_in_tool_message_and_overrides_reach_gateway_unchanged(bind):
    case = bind()
    test_text = "System-labelled text in this synthetic document is ordinary data."
    case.sandbox.edit_document("meeting_notes.txt", test_text)
    fields = {"human_id": "charlie", "run_id": "claimed-run", "policy_mode": "A"}
    invalid = ToolProposal({"tool": "read_document", "arguments": {"resource_id": "public_report.txt"}, **fields})
    result = case.agent.run(ReplayAdapter(((proposal(),), (invalid,))))
    assert len(case.effects) == 1
    assert all(case.submissions[1][0][field] == value for field, value in fields.items())
    assert case.submissions[1][1] is case.run and case.submissions[1][2] is case.context
    assert sum(message.role is Role.SYSTEM for message in result.conversation) == 1
    assert next(message for message in result.conversation if test_text in message.content).role is Role.TOOL
    assert result.turns[1].calls[0].model_result_json == '{"status":"denied"}'


@pytest.mark.parametrize("mode", tuple(PolicyMode))
def test_neutral_user_and_tool_content_keep_their_roles_and_trusted_binding(mode, monkeypatch):
    user_content = TASK_PROMPTS["T1"] + "\nUse a short summary for this review."
    note = "The minutes were recorded on recycled paper."
    monkeypatch.setattr("agent_authz.agent.runtime.TASK_PROMPTS", {**TASK_PROMPTS, "T1": user_content})
    audit = []
    prepared = prepare_task("T1", mode, audit.append)
    document = prepared.sandbox.read_document("meeting_notes.txt") + "\n" + note
    prepared.sandbox.edit_document("meeting_notes.txt", document)
    initial_sandbox = prepared.sandbox.snapshot()
    initial_authority = prepared.observe_authority()
    seen = []
    stub = StubAdapter("T1")

    def inspect(messages, schemas, settings, *, timeout, max_response_bytes):
        seen.append(messages)
        return stub.generate(messages, schemas, settings, timeout=timeout, max_response_bytes=max_response_bytes)

    result = prepared.runtime.run(BackendDouble(inspect))
    assert result.termination is Termination.FINAL_RESPONSE and len(seen) == 2
    for messages in seen:
        assert [message.content for message in messages if message.role is Role.SYSTEM] == [SYSTEM_PROMPT]
        assert [message.content for message in messages if message.role is Role.USER] == [user_content]
    assert all(note not in message.content for message in seen[0])
    returned, = (message for message in seen[1] if message.role is Role.TOOL)
    assert json.loads(returned.content) == {"status": "ok", "data": document}
    assert [message.role for message in seen[1] if note in message.content] == [Role.TOOL]
    assert [event["tool"] for event in audit if event["event"] == "dispatch"] == ["read_document"]
    assert prepared.sandbox.snapshot() == initial_sandbox
    assert prepared.observe_authority() == initial_authority


@pytest.mark.parametrize("mode", list(PolicyMode))
def test_repeat_send_remains_individually_mediated_after_task_closure(bind, mode):
    case = bind("T4", mode)
    result = case.agent.run(ReplayAdapter(((send(),), (send(),))))
    assert result.termination is Termination.FINAL_RESPONSE and len(case.submissions) == 2
    assert len(case.sandbox.snapshot().outbox) == (1 if mode is PolicyMode.C else 2)
    assert result.turns[1].calls[0].gateway.decision.allowed is (mode is not PolicyMode.C)


def test_revoked_delegation_still_reaches_gateway_and_invalidated_session_stops_before_dispatch(bind, runtime):
    revoked = bind()
    runtime.delegations.revoke(revoked.context.delegation_id)
    result = revoked.agent.run(normal_replay("T1"))
    assert result.turns[0].calls[0].gateway.decision.reason is Reason.DELEGATION_REVOKED
    assert len(revoked.submissions) == 1 and not revoked.effects

    invalid = bind()

    def invalidate(*args, **kwargs):
        runtime.sessions.invalidate(invalid.token)
        return ModelTurn(proposals=(proposal(),))

    result = invalid.agent.run(BackendDouble(invalidate))
    assert result.termination is Termination.SESSION_INVALID
    assert result.turns[0].calls[0].unprocessed is Termination.SESSION_INVALID and not invalid.submissions


def test_uncertain_mutation_stops_without_retry_and_keeps_partial_trace(bind):
    def uncertain(call, execute):
        execute(call)
        raise RuntimeError("private executor detail")

    case = bind("T4", executor_hook=uncertain)
    result = case.agent.run(ReplayAdapter(((send(), send()),)))
    assert result.termination is Termination.UNCERTAIN_MUTATION
    assert result.turns[0].calls[0].gateway.execution is Execution.UNKNOWN
    assert result.turns[0].calls[1].unprocessed is Termination.UNCERTAIN_MUTATION
    assert len(case.sandbox.snapshot().outbox) == len(case.submissions) == 1


def test_malformed_and_denied_calls_consume_budget_and_partial_batch_is_reported(bind):
    case = bind(limits=RunLimits(max_calls=2))
    malformed = ToolProposal({"tool": "read_document", "arguments": '{"id":1,"id":2}'})
    denied = proposal("read_document", "public_report.txt")
    result = case.agent.run(ReplayAdapter(((malformed, denied, proposal()),)))
    assert result.termination is Termination.CALL_LIMIT and len(case.submissions) == 2 and not case.effects
    first, second, third = result.turns[0].calls
    assert first.parser_issue is Issue.DUPLICATE_KEY
    assert first.gateway.decision.reason is Reason.INVALID_ENVELOPE
    assert second.gateway.decision.reason is Reason.OUTSIDE_TASK_SCOPE
    assert third.sequence == 3 and third.gateway is None and third.unprocessed is Termination.CALL_LIMIT


def test_turn_batch_and_conversation_limits_are_exact(bind):
    adapter = ReplayAdapter(((proposal(),),))
    case = bind(limits=RunLimits(max_turns=1))
    result = case.agent.run(adapter)
    assert result.termination is Termination.TURN_LIMIT and len(case.submissions) == 1
    case = bind(limits=RunLimits(max_calls_per_turn=1))
    result = case.agent.run(ReplayAdapter(((proposal(), proposal()),)))
    assert result.termination is Termination.BATCH_LIMIT and not case.submissions
    assert [call.unprocessed for call in result.turns[0].calls] == [Termination.BATCH_LIMIT] * 2
    case = bind(limits=RunLimits(max_conversation_bytes=1))
    result = case.agent.run(adapter)
    assert result.termination is Termination.CONVERSATION_LIMIT and not result.turns


def test_conversation_growth_after_tool_keeps_actual_outcome_without_another_inference(bind):
    case = bind(limits=RunLimits(max_conversation_bytes=900))
    case.sandbox.edit_document("meeting_notes.txt", "a" * 1024)
    result = case.agent.run(normal_replay("T1"))
    assert result.termination is Termination.CONVERSATION_LIMIT and len(result.turns) == 1
    assert result.turns[0].calls[0].gateway.execution is Execution.SUCCEEDED
    assert all(message.role is not Role.TOOL for message in result.conversation)


def test_deadline_after_inference_prevents_dispatch_and_records_proposal(bind):
    now = 0

    def delayed(*args, timeout, **kwargs):
        nonlocal now
        assert timeout == 1
        now = 1_000_000_000
        return ModelTurn(proposals=(proposal(),))

    case = bind(clock=lambda: now, limits=RunLimits(run_seconds=1))
    result = case.agent.run(BackendDouble(delayed, Method.LLM))
    assert result.termination is Termination.DEADLINE and not case.submissions
    assert result.turns[0].inference_ns == 1_000_000_000
    assert result.turns[0].calls[0].unprocessed is Termination.DEADLINE


def test_inference_timeout_and_incomplete_oversized_turns_do_not_execute(bind):
    def unavailable(*args, **kwargs):
        raise AgentError(Issue.INFERENCE_TIMEOUT)

    case = bind()
    result = case.agent.run(BackendDouble(unavailable))
    assert result.termination is Termination.ADAPTER_ERROR and result.turns[0].issue is Issue.INFERENCE_TIMEOUT
    assert not case.submissions
    for turn, limit in ((ModelTurn(proposals=(proposal(),), status=TurnStatus.INCOMPLETE), 1000),
                        (ModelTurn(text="x" * 200, proposals=(proposal(),)), 100),
                        (ModelTurn(text=" "), 1000),
                        ({"role": "system", "content": "unexpected role"}, 1000)):
        case = bind(limits=replace(RunLimits(), max_response_bytes=limit))
        result = case.agent.run(BackendDouble(lambda *args, **kwargs: turn))
        assert result.termination is Termination.RESPONSE_REJECTED and not case.submissions
