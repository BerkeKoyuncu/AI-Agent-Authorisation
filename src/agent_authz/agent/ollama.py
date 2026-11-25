"""Opt-in, loopback-only Ollama chat transport with local model checks."""

from collections.abc import Callable
from http.client import HTTPConnection, HTTPException
import json
from math import isfinite
import re
from time import monotonic

from .models import (
    AgentError, Backend, GenerationSettings, Issue, Message, Method, ModelTurn, Role, ToolProposal, TurnStatus,
)
from .parser import decode_json


DEFAULT_ENDPOINT = "http://127.0.0.1:11434/api/chat"
_MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*(?::[A-Za-z0-9][A-Za-z0-9_.-]*)?\Z")
_DIGEST = re.compile(r"[a-fA-F0-9]{64}\Z")


def _canonical_model(name: str) -> str:
    return name if ":" in name else f"{name}:latest"


def _message(message: Message) -> dict[str, object]:
    result: dict[str, object] = {"role": message.role, "content": message.content}
    if message.role is Role.TOOL:
        result["tool_name"] = message.tool_name
    if message.calls:
        result["tool_calls"] = [{
            "type": "function",
            "function": {"index": index, "name": call.tool, "arguments": json.loads(call.arguments_json)},
        } for index, call in enumerate(message.calls)]
    return result


def _proposal(value: object) -> ToolProposal:
    if type(value) is not dict:
        return ToolProposal(value, issue=Issue.MALFORMED_PROPOSAL)
    function = value.get("function")
    if (value.keys() - {"type", "function", "id"} or value.get("type", "function") != "function"
            or type(function) is not dict or function.keys() - {"index", "name", "arguments"}
            or not {"name", "arguments"} <= function.keys()):
        return ToolProposal(value, provider_id=value.get("id"), issue=Issue.MALFORMED_PROPOSAL)
    return ToolProposal({"tool": function["name"], "arguments": function["arguments"]},
                        value.get("id"), function.get("index"))


class OllamaAdapter:
    def __init__(
        self, model: str, *, confirm_local_only: bool = False, endpoint: str = DEFAULT_ENDPOINT,
        connection_factory: Callable[..., HTTPConnection] = HTTPConnection,
    ) -> None:
        if (confirm_local_only is not True or type(endpoint) is not str or endpoint != DEFAULT_ENDPOINT
                or type(model) is not str or len(model) > 120 or not _MODEL_NAME.fullmatch(model)
                or model.lower().endswith(("-cloud", ":cloud"))):
            raise AgentError(Issue.INVALID_CONFIGURATION)
        self.backend = Backend(Method.LLM, "ollama-local", _canonical_model(model))
        self._connect = connection_factory

    def _request(
        self, method: str, path: str, body: dict[str, object] | None, deadline: float, limit: int,
    ) -> object:
        timeout = deadline - monotonic()
        if timeout <= 0:
            raise AgentError(Issue.INFERENCE_TIMEOUT)
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8") if body else None
        try:
            # HTTPConnection operates directly on this numeric address and does not consult proxy variables.
            connection = self._connect("127.0.0.1", 11434, timeout=timeout)
            try:
                connection.request(method, path, body=payload, headers={"Content-Type": "application/json"})
                with connection.getresponse() as response:
                    if 300 <= response.status < 400:
                        raise AgentError(Issue.REDIRECT_REJECTED)
                    if response.status == 404:
                        raise AgentError(Issue.MODEL_UNAVAILABLE)
                    if response.status != 200:
                        raise AgentError(Issue.INVALID_RESPONSE)
                    raw = response.read(limit + 1)
            finally:
                connection.close()
        except TimeoutError:
            raise AgentError(Issue.INFERENCE_TIMEOUT) from None
        except (OSError, HTTPException):
            raise AgentError(Issue.CONNECTION_FAILED) from None
        return decode_json(raw, limit)

    def _check_model(self, deadline: float, limit: int) -> str | None:
        roster = self._request("GET", "/api/tags", None, deadline, limit)
        if type(roster) is not dict or type(roster.get("models")) is not list:
            raise AgentError(Issue.INVALID_RESPONSE)
        matches = [entry for entry in roster["models"] if type(entry) is dict
                   and entry.get("model", entry.get("name")) == self.backend.model]
        if len(matches) != 1:
            raise AgentError(Issue.MODEL_UNAVAILABLE)
        [entry] = matches
        size, details = entry.get("size"), entry.get("details")
        if (type(size) is not int or size <= 0 or type(details) is not dict or details.get("format") != "gguf"
                or entry.get("remote_model") or entry.get("remote_host")):
            raise AgentError(Issue.MODEL_UNAVAILABLE)
        info = self._request("POST", "/api/show", {"model": self.backend.model}, deadline, limit)
        if type(info) is not dict:
            raise AgentError(Issue.INVALID_RESPONSE)
        if info.get("remote_model") or info.get("remote_host"):
            raise AgentError(Issue.MODEL_UNAVAILABLE)
        capabilities = info.get("capabilities")
        if type(capabilities) is not list or "tools" not in capabilities:
            raise AgentError(Issue.TOOLS_UNSUPPORTED)
        digest = entry.get("digest")
        return digest if type(digest) is str and len(digest) == 64 and _DIGEST.fullmatch(digest) else None

    def generate(
        self, messages: tuple[Message, ...], schemas: list[dict[str, object]], settings: GenerationSettings,
        *, timeout: float, max_response_bytes: int,
    ) -> ModelTurn:
        if type(timeout) not in (int, float) or not isfinite(timeout) or timeout <= 0:
            raise AgentError(Issue.INVALID_CONFIGURATION)
        deadline = monotonic() + timeout
        digest = self._check_model(deadline, max_response_bytes)
        result = self._request("POST", "/api/chat", {
            "model": self.backend.model,
            "messages": [_message(message) for message in messages],
            "tools": [{"type": "function", "function": schema} for schema in schemas],
            "options": {"temperature": settings.temperature, "seed": settings.seed, "num_predict": settings.max_tokens},
            "stream": False,
        }, deadline, max_response_bytes)
        if type(result) is not dict or type(result.get("message")) is not dict or type(result.get("done")) is not bool:
            raise AgentError(Issue.INVALID_RESPONSE)
        model = result.get("model")
        message = result["message"]
        text, calls = message.get("content", ""), message.get("tool_calls", [])
        if (type(model) is not str or len(model) > 128 or _canonical_model(model) != self.backend.model
                or message.get("role") != "assistant" or type(text) is not str or type(calls) is not list):
            raise AgentError(Issue.INVALID_RESPONSE)
        status = (TurnStatus.READY if result["done"] and result.get("done_reason") in (None, "stop")
                  else TurnStatus.INCOMPLETE)
        return ModelTurn(text, tuple(_proposal(call) for call in calls), status, model, digest)
