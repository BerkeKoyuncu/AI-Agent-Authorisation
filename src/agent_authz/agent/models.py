"""Provider-neutral messages, configurations and trusted run observations."""

from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from typing import Protocol

from ..gateway.models import GatewayResult


class Issue(StrEnum):
    INVALID_RESPONSE = "invalid_response"
    INVALID_JSON = "invalid_json"
    DUPLICATE_KEY = "duplicate_json_key"
    STRUCTURE_LIMIT = "structure_limit"
    MALFORMED_PROPOSAL = "malformed_proposal"
    INVALID_CORRELATION = "invalid_correlation"
    RESPONSE_TOO_LARGE = "response_too_large"
    INVALID_CONFIGURATION = "invalid_configuration"
    ADAPTER_FAILURE = "adapter_failure"
    CONNECTION_FAILED = "connection_failed"
    INFERENCE_TIMEOUT = "inference_timeout"
    MODEL_UNAVAILABLE = "model_unavailable"
    TOOLS_UNSUPPORTED = "tools_unsupported"
    REDIRECT_REJECTED = "redirect_rejected"


class AgentError(Exception):
    def __init__(self, issue: Issue) -> None:
        super().__init__(issue.value)
        self.issue = issue


class Method(StrEnum):
    REPLAY = "replay"
    STUB = "stub"
    LLM = "llm"


class Role(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass(frozen=True, slots=True)
class Backend:
    method: Method
    name: str
    model: str | None = None


@dataclass(frozen=True, slots=True)
class ToolProposal:
    """Untrusted decoded values. The runtime snapshots them before use."""

    envelope: object
    provider_id: object = None
    provider_index: object = None
    issue: Issue | None = None


@dataclass(frozen=True, slots=True)
class HistoryCall:
    sequence: int
    tool: str
    arguments_json: str


@dataclass(frozen=True, slots=True)
class Message:
    role: Role
    content: str = ""
    calls: tuple[HistoryCall, ...] = ()
    tool_name: str | None = None
    sequence: int | None = None


class TurnStatus(StrEnum):
    READY = "ready"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True, slots=True)
class ModelTurn:
    text: str = ""
    proposals: tuple[ToolProposal, ...] = ()
    status: TurnStatus = TurnStatus.READY
    model: str | None = None
    digest: str | None = None


@dataclass(frozen=True, slots=True)
class GenerationSettings:
    temperature: float = 0.0
    seed: int = 42
    max_tokens: int = 1024

    def __post_init__(self) -> None:
        if (type(self.temperature) not in (int, float) or not 0 <= self.temperature <= 2
                or type(self.seed) is not int or not 0 <= self.seed < 2**31
                or type(self.max_tokens) is not int or not 1 <= self.max_tokens < 2**31):
            raise AgentError(Issue.INVALID_CONFIGURATION)


@dataclass(frozen=True, slots=True)
class RunLimits:
    max_turns: int = 10
    max_calls: int = 20
    max_calls_per_turn: int = 8
    max_response_bytes: int = 1_048_576
    max_conversation_bytes: int = 262_144
    inference_seconds: float = 60
    run_seconds: float = 180

    def __post_init__(self) -> None:
        counts = (self.max_turns, self.max_calls, self.max_calls_per_turn, self.max_response_bytes,
                  self.max_conversation_bytes)
        durations = (self.inference_seconds, self.run_seconds)
        if (any(type(value) is not int or value < 1 for value in counts)
                or any(type(value) not in (int, float) or not 1e-9 <= value <= 86_400 or not isfinite(value)
                       for value in durations)):
            raise AgentError(Issue.INVALID_CONFIGURATION)


class ModelAdapter(Protocol):
    backend: Backend

    def generate(
        self, messages: tuple[Message, ...], schemas: list[dict[str, object]], settings: GenerationSettings,
        *, timeout: float, max_response_bytes: int,
    ) -> ModelTurn: ...


class Termination(StrEnum):
    FINAL_RESPONSE = "final_response"
    TURN_LIMIT = "turn_limit"
    CALL_LIMIT = "call_limit"
    BATCH_LIMIT = "batch_limit"
    CONVERSATION_LIMIT = "conversation_limit"
    DEADLINE = "deadline"
    SESSION_INVALID = "session_invalid"
    ADAPTER_ERROR = "adapter_error"
    RESPONSE_REJECTED = "response_rejected"
    GATEWAY_ERROR = "gateway_error"
    UNCERTAIN_MUTATION = "uncertain_mutation"


@dataclass(frozen=True, slots=True)
class ToolObservation:
    sequence: int
    proposal_json: str | None
    provider_id: str | None
    provider_index: int | None
    parser_issue: Issue | None
    gateway: GatewayResult | None = None
    model_result_json: str | None = None
    unprocessed: Termination | None = None


@dataclass(frozen=True, slots=True)
class TurnObservation:
    number: int
    text: str | None
    adapter_ns: int
    inference_ns: int | None
    status: TurnStatus | None
    proposed_count: int | None
    calls: tuple[ToolObservation, ...] = ()
    issue: Issue | None = None
    model: str | None = None
    digest: str | None = None


@dataclass(frozen=True, slots=True)
class RunResult:
    backend: Backend
    task_id: str
    run_id: str
    prompt_version: str
    settings: GenerationSettings
    limits: RunLimits
    turns: tuple[TurnObservation, ...]
    conversation: tuple[Message, ...]
    final_response: str | None
    termination: Termination
    elapsed_ns: int
