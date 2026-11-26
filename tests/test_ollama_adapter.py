import json

import pytest

from agent_authz.agent.models import AgentError, GenerationSettings, Issue, Message, Method, Role, Termination, TurnStatus
from agent_authz.agent.ollama import OllamaAdapter
from agent_authz.agent.runtime import prepare_task
from agent_authz.gateway import Execution, PolicyMode, tool_schemas
from agent_authz.sandbox.fixtures import MEETING_FACTS


DIGEST = "f" * 64
LOCAL = {"models": [{"model": "local-model:latest", "size": 100, "digest": DIGEST,
                     "details": {"format": "gguf"}}]}
CAPABILITIES = {"capabilities": ["completion", "tools"]}
SCHEMAS = tool_schemas()


class Response:
    def __init__(self, body, status=200):
        self.status = status
        self.body = body if type(body) is bytes else json.dumps(body).encode("utf-8")
        self.read_limits = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, amount):
        self.read_limits.append(amount)
        return self.body[:amount]


class LocalTransport:
    def __init__(self, responses):
        self.queue = iter(responses)
        self.requests = []
        self.destinations = []
        self.closed = 0

    def connect(self, host, port, *, timeout):
        self.destinations.append((host, port, timeout))
        return self

    def request(self, method, path, *, body, headers):
        self.requests.append((method, path, json.loads(body) if body is not None else None, headers))

    def getresponse(self):
        item = next(self.queue)
        if isinstance(item, Exception):
            raise item
        return item if isinstance(item, Response) else Response(item)

    def close(self):
        self.closed += 1


def response(content="", calls=None, **extra):
    message = {"role": "assistant", "content": content}
    if calls is not None:
        message["tool_calls"] = calls
    return {"model": "local-model:latest", "message": message, "done": True, "done_reason": "stop", **extra}


def call(name="read_document", arguments=None, **fields):
    if arguments is None:
        arguments = {"resource_id": "meeting_notes.txt"}
    return {"type": "function", "function": {"index": 0, "name": name, "arguments": arguments}, **fields}


def adapter(transport):
    return OllamaAdapter("local-model", confirm_local_only=True, connection_factory=transport.connect)


def test_documented_protocol_uses_shared_schema_format_and_read_result_in_followup(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://example.invalid:8080")
    model_calls = [call(id="one"), call(arguments='{"resource_id":"public_report.txt"}', id="one")]
    final_text = " ".join(MEETING_FACTS)
    transport = LocalTransport([LOCAL, CAPABILITIES, response(calls=model_calls), LOCAL, CAPABILITIES, response(final_text)])
    settings = GenerationSettings(temperature=0.25, seed=8, max_tokens=64)
    prepared = prepare_task("T1", PolicyMode.C, lambda event: None, settings=settings)
    run = prepared.runtime.run(adapter(transport))
    assert run.backend.method is Method.LLM and run.backend.name == "ollama-local"
    assert run.termination is Termination.FINAL_RESPONSE and run.final_response == final_text
    assert [turn.model for turn in run.turns] == ["local-model:latest"] * 2
    assert [turn.digest for turn in run.turns] == [DIGEST] * 2
    assert all(turn.inference_ns is not None for turn in run.turns)
    assert [call.gateway.execution for call in run.turns[0].calls] == [Execution.SUCCEEDED, Execution.NOT_DISPATCHED]
    assert [(method, path) for method, path, _, _ in transport.requests] == [
        ("GET", "/api/tags"), ("POST", "/api/show"), ("POST", "/api/chat"),
    ] * 2
    assert all((host, port) == ("127.0.0.1", 11434) and 0 < timeout <= 60 for host, port, timeout in transport.destinations)
    assert transport.closed == 6

    first, follow_up = (transport.requests[i][2] for i in (2, 5))
    assert first["stream"] is False and first["model"] == "local-model:latest"
    assert first["tools"] == follow_up["tools"] == [{"type": "function", "function": s} for s in SCHEMAS]
    assert first["options"] == {"temperature": 0.25, "seed": 8, "num_predict": 64}
    assert [message["role"] for message in first["messages"]] == ["system", "user"]
    messages = follow_up["messages"]
    assistant = messages[2]
    assert assistant["role"] == "assistant"
    assert [tool["function"]["index"] for tool in assistant["tool_calls"]] == [0, 1]
    assert [tool["function"]["arguments"] for tool in assistant["tool_calls"]] == [
        {"resource_id": "meeting_notes.txt"}, {"resource_id": "public_report.txt"},
    ]
    assert all(message["role"] == "tool" and message["tool_name"] == "read_document" for message in messages[3:])
    assert [json.loads(message["content"]) for message in messages[3:]] == [
        {"status": "ok", "data": "\n".join(MEETING_FACTS)}, {"status": "denied"},
    ]
    assert run.run_id not in repr(first) + repr(follow_up)
    assert "delegation_id" not in repr(first) + repr(follow_up)


def test_single_call_and_text_are_translated_without_executing_tools():
    transport = LocalTransport([LOCAL, CAPABILITIES, response("Checking", [call()])])
    result = adapter(transport).generate((Message(Role.USER, "Synthetic question"),), SCHEMAS, GenerationSettings(),
                                         timeout=1, max_response_bytes=4096)
    assert result.text == "Checking" and result.status is TurnStatus.READY
    assert result.proposals[0].envelope == {"tool": "read_document", "arguments": {"resource_id": "meeting_notes.txt"}}
    assert len(transport.requests) == 3


@pytest.mark.parametrize(("bad_response", "issue"), [
    (Response(b"{"), Issue.INVALID_JSON),
    (Response(b'{"done":true,"done":false}'), Issue.DUPLICATE_KEY),
    (Response(b'{"message":{"tool_calls":[{"function":{"name":"a","arguments":{"x":1,"x":2}}}]}}'),
     Issue.DUPLICATE_KEY),
    (Response({"model": "local-model:latest", "message": {"role": "system"}, "done": True}), Issue.INVALID_RESPONSE),
    (Response(response(model="wrong-model")), Issue.INVALID_RESPONSE),
    (Response(response(calls={"invalid": True})), Issue.INVALID_RESPONSE),
    (Response(b"x" * 4097), Issue.RESPONSE_TOO_LARGE),
    (Response({}, 307), Issue.REDIRECT_REJECTED),
    (ConnectionError("unchecked network detail"), Issue.CONNECTION_FAILED),
    (TimeoutError("unchecked timeout detail"), Issue.INFERENCE_TIMEOUT),
])
def test_bad_transport_responses_fail_with_safe_errors_without_fallback(bad_response, issue):
    transport = LocalTransport([LOCAL, CAPABILITIES, bad_response])
    with pytest.raises(AgentError) as error:
        adapter(transport).generate((), SCHEMAS, GenerationSettings(), timeout=1, max_response_bytes=4096)
    assert error.value.issue is issue and str(error.value) == issue.value
    assert len(transport.requests) == transport.closed == 3
    assert all(host == "127.0.0.1" for host, _, _ in transport.destinations)
    if issue is Issue.RESPONSE_TOO_LARGE:
        assert bad_response.read_limits == [4097]


@pytest.mark.parametrize("endpoint", ["http://example.invalid/api/chat", "https://127.0.0.1:11434/api/chat",
                                     "http://localhost:11434/api/chat", "http://127.0.0.1:1234/api/chat"])
def test_reject_other_endpoints_before_transport_creation(endpoint):
    transport = LocalTransport([])
    with pytest.raises(AgentError) as error:
        OllamaAdapter("local-model", confirm_local_only=True, endpoint=endpoint, connection_factory=transport.connect)
    assert error.value.issue is Issue.INVALID_CONFIGURATION and not transport.destinations


@pytest.mark.parametrize(("model", "attested"), [("local-model", False), ("example:cloud", True),
                                                   ("example-cloud", True), ("http://example.invalid/model", True)])
def test_local_model_selection_requires_explicit_confirmation_and_local_tag(model, attested):
    with pytest.raises(AgentError) as error:
        OllamaAdapter(model, confirm_local_only=attested)
    assert error.value.issue is Issue.INVALID_CONFIGURATION


@pytest.mark.parametrize(("catalogue", "info", "issue"), [
    ({"models": []}, CAPABILITIES, Issue.MODEL_UNAVAILABLE),
    ({"models": [{**LOCAL["models"][0], "remote_host": "https://example.invalid"}]}, CAPABILITIES, Issue.MODEL_UNAVAILABLE),
    ({"models": [{**LOCAL["models"][0], "remote_model": "remote"}]}, CAPABILITIES, Issue.MODEL_UNAVAILABLE),
    ({"models": [{**LOCAL["models"][0], "size": 0}]}, CAPABILITIES, Issue.MODEL_UNAVAILABLE),
    (LOCAL, {"capabilities": ["completion"]}, Issue.TOOLS_UNSUPPORTED),
])
def test_missing_remote_and_unsupported_models_are_rejected_before_chat(catalogue, info, issue):
    transport = LocalTransport([catalogue, info])
    with pytest.raises(AgentError) as error:
        adapter(transport).generate((), SCHEMAS, GenerationSettings(), timeout=1, max_response_bytes=4096)
    assert error.value.issue is issue
    assert not any(path == "/api/chat" for _, path, _, _ in transport.requests)


def test_malformed_provider_call_is_observed_and_mediated_as_rejection():
    initial = response(calls=[call(policy_mode="A"), call(arguments="{")])
    transport = LocalTransport([LOCAL, CAPABILITIES, initial, LOCAL, CAPABILITIES, response("No tool result available.")])
    audit = []
    task = prepare_task("T1", PolicyMode.C, audit.append)
    result = task.runtime.run(adapter(transport))
    assert [item.parser_issue for item in result.turns[0].calls] == [Issue.MALFORMED_PROPOSAL, Issue.INVALID_JSON]
    assert all(not item.gateway.dispatched for item in result.turns[0].calls)
    assert "policy_mode" in result.turns[0].calls[0].proposal_json
    assert not any(event["event"] == "dispatch" for event in audit)
    history = transport.requests[5][2]["messages"]
    assert [item["tool_name"] for item in history if item["role"] == "tool"] == ["invalid_tool_call"] * 2


def test_truncated_tool_call_response_cannot_execute():
    transport = LocalTransport([LOCAL, CAPABILITIES, response(calls=[call()], done_reason="length")])
    task = prepare_task("T1", PolicyMode.C, lambda event: None)
    result = task.runtime.run(adapter(transport))
    assert result.termination is Termination.RESPONSE_REJECTED
    assert result.turns[0].status is TurnStatus.INCOMPLETE
    assert result.turns[0].calls[0].gateway is None
