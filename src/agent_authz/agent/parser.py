"""Strict JSON parsing and detached snapshots for untrusted proposals."""

from dataclasses import dataclass
import json
from math import isfinite
import re

from .models import AgentError, HistoryCall, Issue, ToolProposal


MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 16_384
MAX_ARGUMENT_BYTES = 262_144
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_TOOL_NAME = re.compile(r"[A-Za-z0-9_]{1,64}\Z")


def _byte_length(value: str, limit: int) -> int:
    if len(value) > limit:
        raise AgentError(Issue.RESPONSE_TOO_LARGE)
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise AgentError(Issue.INVALID_JSON) from None
    if size > limit:
        raise AgentError(Issue.RESPONSE_TOO_LARGE)
    return size


def encode_json(value: object, limit: int) -> str:
    """Bound and serialise built-in JSON values without coercion or custom hooks."""
    remaining = limit
    nodes = MAX_JSON_NODES

    def check(item: object, depth: int) -> None:
        nonlocal remaining, nodes
        nodes -= 1
        remaining -= 1
        if depth > MAX_JSON_DEPTH or nodes < 0:
            raise AgentError(Issue.STRUCTURE_LIMIT)
        if remaining < 0:
            raise AgentError(Issue.RESPONSE_TOO_LARGE)
        kind = type(item)
        if kind is str:
            remaining -= _byte_length(item, remaining)
        elif kind is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise AgentError(Issue.INVALID_JSON)
                check(key, depth + 1)
                check(child, depth + 1)
        elif kind is list:
            for child in item:
                check(child, depth + 1)
        elif item is None or kind is bool:
            return
        elif kind is int and item.bit_length() <= 4096:
            remaining -= max(1, int(item.bit_length() * 0.30103))
        elif kind is float and isfinite(item):
            remaining -= len(repr(item))
        else:
            raise AgentError(Issue.INVALID_JSON)
        if remaining < 0:
            raise AgentError(Issue.RESPONSE_TOO_LARGE)

    check(value, 0)
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    _byte_length(encoded, limit)
    return encoded


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AgentError(Issue.DUPLICATE_KEY)
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise AgentError(Issue.INVALID_JSON)


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise AgentError(Issue.INVALID_JSON)
    return parsed


def decode_json(raw: str | bytes, limit: int) -> object:
    if type(raw) not in (str, bytes):
        raise AgentError(Issue.INVALID_JSON)
    try:
        if type(raw) is bytes:
            if len(raw) > limit:
                raise AgentError(Issue.RESPONSE_TOO_LARGE)
            raw = raw.decode("utf-8")
        _byte_length(raw, limit)
        depth = 0
        quoted = escape = False
        for character in raw:
            if quoted:
                if escape:
                    escape = False
                elif character == "\\":
                    escape = True
                elif character == '"':
                    quoted = False
            elif character == '"':
                quoted = True
            elif character in "[{":
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    raise AgentError(Issue.STRUCTURE_LIMIT)
            elif character in "]}":
                depth -= 1
        decoded = json.loads(raw, object_pairs_hook=_unique_keys, parse_constant=_reject_constant, parse_float=_finite_float)
    except (ValueError, RecursionError):
        raise AgentError(Issue.INVALID_JSON) from None
    encode_json(decoded, limit)
    return decoded


def safe_identifier(value: object) -> bool:
    return type(value) is str and len(value) <= 128 and _IDENTIFIER.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class ParsedProposal:
    raw_json: str | None
    request_json: str | None
    call: HistoryCall
    provider_id: str | None
    provider_index: int | None
    issue: Issue | None


def parse_proposal(proposal: ToolProposal, sequence: int, limit: int) -> ParsedProposal:
    identifier = proposal.provider_id
    index = proposal.provider_index
    provider_id = identifier if safe_identifier(identifier) else None
    provider_index = index if type(index) is int and 0 <= index < 2**31 else None
    raw_json = None
    try:
        raw_json = encode_json(proposal.envelope, limit)
        raw = json.loads(raw_json)
        if (identifier is not None and provider_id is None) or (index is not None and provider_index is None):
            raise AgentError(Issue.INVALID_CORRELATION)
        if proposal.issue is not None:
            raise AgentError(proposal.issue if type(proposal.issue) is Issue else Issue.MALFORMED_PROPOSAL)
        if type(raw) is not dict or "tool" not in raw or "arguments" not in raw or type(raw["tool"]) is not str:
            raise AgentError(Issue.MALFORMED_PROPOSAL)
        arguments = raw["arguments"]
        if type(arguments) is str:
            arguments = decode_json(arguments, min(limit, MAX_ARGUMENT_BYTES))
        if type(arguments) is not dict:
            raise AgentError(Issue.MALFORMED_PROPOSAL)
        argument_json = encode_json(arguments, min(limit, MAX_ARGUMENT_BYTES))
        normalised = encode_json({**raw, "arguments": arguments}, limit)
        name = raw["tool"]
        call = (HistoryCall(sequence, name, argument_json) if len(name) <= 64 and _TOOL_NAME.fullmatch(name)
                else HistoryCall(sequence, "invalid_tool_call", "{}"))
        return ParsedProposal(raw_json, normalised, call, provider_id, provider_index, None)
    except AgentError as error:
        return ParsedProposal(raw_json, None, HistoryCall(sequence, "invalid_tool_call", "{}"),
                              provider_id, provider_index, error.issue)
