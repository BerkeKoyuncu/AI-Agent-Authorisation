"""Single-run conversation loop over a trusted binding and the existing gateway."""

from collections.abc import Callable
from copy import deepcopy
from dataclasses import asdict, dataclass
import json
from time import monotonic_ns

from ..delegation import DelegationManager, DelegationRecord, RuntimeExecutionContext
from ..gateway import Execution, Gateway, PolicyMode, tool_schemas
from ..identity.errors import AuthorityError
from ..identity.principals import IdentityStore, Principal, PrincipalKind
from ..identity.sessions import RunBinding, SessionManager
from ..sandbox import Fixture, SandboxEnvironment
from ..tasks import TASK_CATALOGUE
from .models import (
    AgentError, GenerationSettings, Issue, Message, Method, ModelAdapter, ModelTurn, Role, RunLimits,
    RunResult, Termination, ToolObservation, ToolProposal, TurnObservation, TurnStatus,
)
from .parser import MAX_JSON_NODES, ParsedProposal, encode_json, parse_proposal, safe_identifier
from .prompts import PROMPT_VERSION, SYSTEM_PROMPT, TASK_PROMPTS


_SECOND_NS = 1_000_000_000


class _Conversation:
    def __init__(self, limit: int) -> None:
        self.messages: list[Message] = []
        self._limit = limit
        self._size = 2  # The enclosing JSON array.

    def append(self, message: Message) -> bool:
        size = len(json.dumps(asdict(message), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        size += bool(self.messages)
        if self._size + size > self._limit:
            return False
        self.messages.append(message)
        self._size += size
        return True


def _parse_turn(turn: object, first_sequence: int, limit: int) -> tuple[ParsedProposal, ...]:
    if (type(turn) is not ModelTurn or type(turn.text) is not str or type(turn.proposals) is not tuple
            or type(turn.status) is not TurnStatus):
        raise AgentError(Issue.INVALID_RESPONSE)
    if len(turn.proposals) > MAX_JSON_NODES:
        raise AgentError(Issue.STRUCTURE_LIMIT)
    remaining = limit - len(encode_json(turn.text, limit).encode("utf-8"))
    if turn.status is TurnStatus.READY and not turn.proposals and not turn.text.strip():
        raise AgentError(Issue.INVALID_RESPONSE)
    if len(turn.proposals) > remaining:
        raise AgentError(Issue.RESPONSE_TOO_LARGE)
    parsed = []
    for sequence, proposal in enumerate(turn.proposals, first_sequence):
        if type(proposal) is not ToolProposal:
            proposal = ToolProposal(None, issue=Issue.MALFORMED_PROPOSAL)
        call = parse_proposal(proposal, sequence, remaining)
        if call.raw_json is None and call.issue is Issue.RESPONSE_TOO_LARGE:
            raise AgentError(Issue.RESPONSE_TOO_LARGE)
        remaining -= 1 + (len(call.raw_json.encode("utf-8")) if call.raw_json else 0)
        remaining -= len(call.provider_id or "") + (len(str(call.provider_index)) if call.provider_index is not None else 0)
        if remaining < 0:
            raise AgentError(Issue.RESPONSE_TOO_LARGE)
        parsed.append(call)
    return tuple(parsed)


def _unprocessed(proposal: ParsedProposal, why: Termination) -> ToolObservation:
    return ToolObservation(proposal.call.sequence, proposal.raw_json, proposal.provider_id, proposal.provider_index,
                           proposal.issue, unprocessed=why)


class AgentRuntime:
    """Own a single trusted run. Adapters receive only detached model data."""

    def __init__(
        self, task_id: str, sessions: SessionManager, gateway: Gateway, run: RunBinding,
        context: RuntimeExecutionContext, *, limits: RunLimits = RunLimits(),
        settings: GenerationSettings = GenerationSettings(), clock: Callable[[], int] = monotonic_ns,
    ) -> None:
        if task_id not in TASK_PROMPTS or context.task_id != task_id or context.run is not run:
            raise AgentError(Issue.INVALID_CONFIGURATION)
        self._task_id = task_id
        self._run = run
        self._sessions = sessions
        self._gateway = gateway
        self._context = context
        self._limits = limits
        self._settings = settings
        self._clock = clock
        self._used = False

    def _stop(self, deadline: int) -> Termination | None:
        if self._clock() >= deadline:
            return Termination.DEADLINE
        try:
            self._sessions.validate_run(self._run)
        except AuthorityError:
            return Termination.SESSION_INVALID
        return None

    def run(
        self, adapter: ModelAdapter, *, observe_attempt: Callable[[int, object], None] | None = None,
    ) -> RunResult:
        """Run the adapter, optionally recording detached inputs before gateway submission."""
        if self._used:
            raise AgentError(Issue.INVALID_CONFIGURATION)
        self._used = True
        started = self._clock()
        deadline = started + int(self._limits.run_seconds * _SECOND_NS)
        backend = adapter.backend
        conversation = _Conversation(self._limits.max_conversation_bytes)
        turns: list[TurnObservation] = []
        attempted = 0
        next_sequence = 1
        final = None
        termination = None

        for message in (Message(Role.SYSTEM, SYSTEM_PROMPT), Message(Role.USER, TASK_PROMPTS[self._task_id])):
            if not conversation.append(message):
                termination = Termination.CONVERSATION_LIMIT
                break

        for number in range(1, self._limits.max_turns + 1):
            termination = termination or self._stop(deadline)
            if termination is not None:
                break
            begin = self._clock()
            remaining = deadline - begin
            if remaining <= 0:
                termination = Termination.DEADLINE
                break
            allowed_ns = min(remaining, int(self._limits.inference_seconds * _SECOND_NS))
            try:
                turn = adapter.generate(
                    deepcopy(tuple(conversation.messages)), tool_schemas(), deepcopy(self._settings),
                    timeout=allowed_ns / _SECOND_NS, max_response_bytes=self._limits.max_response_bytes,
                )
            except Exception as error:
                elapsed = self._clock() - begin
                issue = error.issue if type(error) is AgentError else Issue.ADAPTER_FAILURE
                turns.append(TurnObservation(number, None, elapsed, elapsed if backend.method is Method.LLM else None,
                                             None, None, issue=issue))
                termination = self._stop(deadline) or Termination.ADAPTER_ERROR
                break
            elapsed = self._clock() - begin
            inference = elapsed if backend.method is Method.LLM else None
            try:
                proposals = _parse_turn(turn, next_sequence, self._limits.max_response_bytes)
            except AgentError as error:
                count = len(turn.proposals) if type(turn) is ModelTurn and type(turn.proposals) is tuple else None
                turns.append(TurnObservation(number, None, elapsed, inference, None, count, issue=error.issue))
                termination = self._stop(deadline) or Termination.RESPONSE_REJECTED
                break
            next_sequence += len(proposals)

            termination = self._stop(deadline)
            issue = None
            if termination is None and elapsed >= allowed_ns:
                termination, issue = Termination.ADAPTER_ERROR, Issue.INFERENCE_TIMEOUT
            if termination is None and turn.status is TurnStatus.INCOMPLETE:
                termination, issue = Termination.RESPONSE_REJECTED, Issue.INVALID_RESPONSE
            if termination is None and len(proposals) > self._limits.max_calls_per_turn:
                termination = Termination.BATCH_LIMIT

            allowance = self._limits.max_calls - attempted
            if termination is None and not conversation.append(Message(
                Role.ASSISTANT, turn.text, tuple(proposal.call for proposal in proposals[:allowance]),
            )):
                termination = Termination.CONVERSATION_LIMIT

            outcomes: list[ToolObservation] = []
            if termination is None and not proposals:
                termination, final = Termination.FINAL_RESPONSE, turn.text
            elif termination is None:
                for proposal in proposals[:allowance]:
                    termination = self._stop(deadline)
                    if termination is not None:
                        break
                    observation, termination = self._forward(proposal, conversation, deadline, observe_attempt)
                    attempted += 1
                    outcomes.append(observation)
                    if termination is not None:
                        break
                if termination is None and attempted >= self._limits.max_calls:
                    termination = Termination.CALL_LIMIT
            if termination is not None:
                outcomes.extend(_unprocessed(p, termination) for p in proposals[len(outcomes):])
            turns.append(TurnObservation(
                number, turn.text, elapsed, inference, turn.status, len(proposals), tuple(outcomes), issue,
                turn.model if safe_identifier(turn.model) else None, turn.digest if safe_identifier(turn.digest) else None,
            ))
            if termination is not None:
                break

        return RunResult(backend, self._task_id, self._run.run_id, PROMPT_VERSION, self._settings, self._limits,
                         tuple(turns), tuple(conversation.messages), final, termination or Termination.TURN_LIMIT,
                         self._clock() - started)

    def _forward(
        self, proposal: ParsedProposal, conversation: _Conversation, deadline: int,
        observe_attempt: Callable[[int, object], None] | None,
    ) -> tuple[ToolObservation, Termination | None]:
        fields = (proposal.call.sequence, proposal.raw_json, proposal.provider_id, proposal.provider_index, proposal.issue)
        request = json.loads(proposal.request_json) if proposal.request_json is not None else None
        if observe_attempt is not None:
            try:
                observe_attempt(proposal.call.sequence, deepcopy(request))
            except Exception:
                stop = Termination.OBSERVATION_ERROR
                return ToolObservation(*fields, unprocessed=stop), stop
            stop = self._stop(deadline)
            if stop is not None:
                return ToolObservation(*fields, unprocessed=stop), stop
        try:
            result = self._gateway.handle(request, self._run, self._context)
        except Exception:
            return ToolObservation(*fields), Termination.GATEWAY_ERROR
        safe = json.dumps(result.model_response(), ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        observation = ToolObservation(*fields, gateway=result, model_result_json=safe)
        fits = conversation.append(Message(Role.TOOL, safe, tool_name=proposal.call.tool, sequence=proposal.call.sequence))
        if result.execution is Execution.UNKNOWN and result.lifecycle == "quarantined":
            return observation, Termination.UNCERTAIN_MUTATION
        return observation, None if fits else Termination.CONVERSATION_LIMIT


@dataclass(frozen=True, slots=True)
class AuthoritySnapshot:
    """Credential-free observation of the trusted records attached to a task."""

    context: RuntimeExecutionContext
    shared_valid: bool
    human: Principal
    agent: Principal
    delegation: DelegationRecord | None


@dataclass(frozen=True, slots=True)
class PreparedTask:
    runtime: AgentRuntime
    sandbox: SandboxEnvironment
    observe_authority: Callable[[], AuthoritySnapshot]


def prepare_task(
    task_id: str, policy: PolicyMode, audit: Callable[[dict[str, object]], None], *,
    limits: RunLimits = RunLimits(), settings: GenerationSettings = GenerationSettings(),
) -> PreparedTask:
    """Create a fresh approved synthetic task with the trusted principal and fixture bindings."""
    task = TASK_CATALOGUE.get(task_id)
    if task is None:
        raise AgentError(Issue.INVALID_CONFIGURATION)
    sessions = SessionManager(IdentityStore())
    proof = sessions.provision_credential(task.human_id)
    token = sessions.authenticate(task.human_id, proof)
    run = sessions.start_run(token, task.agent_id)
    delegations = DelegationManager(sessions)
    pending = delegations.issue(run, task_id)
    delegations.activate(run, pending.delegation_id)
    context = delegations.bind_context(run, pending.delegation_id)
    fixture = Fixture.SUMMARY_SEEDED if task_id == "T5" else Fixture.SUMMARY_ABSENT
    sandbox = SandboxEnvironment(fixture)
    gateway = Gateway(policy, sessions, delegations, sandbox, audit)

    def observe_authority() -> AuthoritySnapshot:
        try:
            sessions.validate_run(run)
        except AuthorityError:
            shared_valid = False
        else:
            shared_valid = True
        try:
            delegation = delegations.lookup(context.delegation_id)
        except AuthorityError:
            delegation = None
        return AuthoritySnapshot(
            context, shared_valid, sessions.identities.lookup(PrincipalKind.HUMAN, run.human_id),
            sessions.identities.lookup(PrincipalKind.AGENT, run.agent_id), delegation,
        )

    runtime = AgentRuntime(task_id, sessions, gateway, run, context, limits=limits, settings=settings)
    return PreparedTask(runtime, sandbox, observe_authority)
