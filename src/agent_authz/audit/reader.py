"""Bounded, read-only JSONL parsing with content-free diagnostics."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from pathlib import Path

from .schema import AuditSchemaError, SchemaIssue, validate_event


MAX_LINE_BYTES = 16 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024


class ReadIssue(StrEnum):
    MISSING_FILE = "missing_file"
    UNREADABLE_FILE = "unreadable_file"
    FILE_LIMIT = "file_limit"
    OVERSIZED_LINE = "oversized_line"
    TRUNCATED_LINE = "truncated_line"
    INVALID_UTF8 = "invalid_utf8"
    MALFORMED_JSON = "malformed_json"
    DUPLICATE_KEY = "duplicate_key"
    NONFINITE_NUMBER = "nonfinite_number"
    NON_OBJECT = "non_object"


class _ParseError(ValueError):
    def __init__(self, issue: ReadIssue) -> None:
        self.issue = issue


@dataclass(frozen=True, slots=True)
class JournalProblem:
    issue: ReadIssue | SchemaIssue
    line: int | None = None


@dataclass(frozen=True, slots=True)
class JournalRecord:
    line: int
    fields: Mapping[str, object]

    @property
    def event(self) -> str:
        return str(self.fields["event"])

    @property
    def request_id(self) -> str:
        return str(self.fields["request_id"])


@dataclass(frozen=True, slots=True)
class Journal:
    records: tuple[JournalRecord, ...]
    problems: tuple[JournalProblem, ...]

    @property
    def invalid_records(self) -> int:
        return sum(problem.line is not None for problem in self.problems)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _ParseError(ReadIssue.DUPLICATE_KEY)
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise _ParseError(ReadIssue.NONFINITE_NUMBER)


def _finite_number(text: str) -> float:
    value = float(text)
    if not isfinite(value):
        _reject_constant(text)
    return value


def _parse(blob: bytes, line: int) -> JournalRecord | JournalProblem:
    if not blob.endswith(b"\n"):
        return JournalProblem(ReadIssue.TRUNCATED_LINE, line)
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return JournalProblem(ReadIssue.INVALID_UTF8, line)
    try:
        value = json.loads(text, object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant, parse_float=_finite_number)
    except _ParseError as error:
        return JournalProblem(error.issue, line)
    except (ValueError, RecursionError):
        return JournalProblem(ReadIssue.MALFORMED_JSON, line)
    if type(value) is not dict:
        return JournalProblem(ReadIssue.NON_OBJECT, line)
    try:
        return JournalRecord(line, validate_event(value))
    except AuditSchemaError as error:
        return JournalProblem(error.issue, line)


def read_journal(
    path: Path, *, max_line_bytes: int = MAX_LINE_BYTES, max_file_bytes: int = MAX_FILE_BYTES,
) -> Journal:
    """Read a trusted local path with byte limits that include line terminators."""
    if any(type(limit) is not int or limit < 1 for limit in (max_line_bytes, max_file_bytes)):
        raise ValueError("Audit byte limits must be positive integers.")
    records: list[JournalRecord] = []
    problems: list[JournalProblem] = []
    total, line = 0, 1
    discarding = False
    try:
        with path.open("rb") as source:
            while chunk := source.readline(min(max_line_bytes + 1, max_file_bytes - total + 1)):
                total += len(chunk)
                if total > max_file_bytes:
                    problems.append(JournalProblem(ReadIssue.FILE_LIMIT))
                    break
                if not discarding:
                    parsed = (JournalProblem(ReadIssue.OVERSIZED_LINE, line)
                              if len(chunk) > max_line_bytes else _parse(chunk, line))
                    if isinstance(parsed, JournalRecord):
                        records.append(parsed)
                    else:
                        problems.append(parsed)
                discarding = not chunk.endswith(b"\n")
                if not discarding:
                    line += 1
    except FileNotFoundError:
        problems.append(JournalProblem(ReadIssue.MISSING_FILE))
    except OSError:
        problems.append(JournalProblem(ReadIssue.UNREADABLE_FILE))
    return Journal(tuple(records), tuple(problems))
