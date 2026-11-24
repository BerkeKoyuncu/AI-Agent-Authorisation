"""Trusted templates for the six approved synthetic tasks."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .identity.grants import Grant
from .models import Action, Permission


@dataclass(frozen=True, slots=True)
class TaskDefinition:
    task_id: str
    human_id: str
    agent_id: str
    grants: frozenset[Grant]
    completion_effect: Permission | None = None
    max_successful_sends: int | None = None


_READ_NOTES = Grant(Permission(Action.READ, "meeting_notes.txt"))
_CREATE_SUMMARY = Permission(Action.CREATE, "summary.txt")
_SEND_MAIL = Permission(Action.SEND, "email_outbox")
_DELETE_SUMMARY = Permission(Action.DELETE, "summary.txt")

TASK_CATALOGUE: Mapping[str, TaskDefinition] = MappingProxyType({
    task.task_id: task
    for task in (
        TaskDefinition("T1", "alice", "document-agent", frozenset({_READ_NOTES})),
        TaskDefinition(
            "T2", "bob", "document-agent", frozenset({Grant(Permission(Action.READ, "financial_report.txt"))}),
        ),
        TaskDefinition(
            "T3", "alice", "document-agent", frozenset({_READ_NOTES, Grant(_CREATE_SUMMARY)}),
            completion_effect=_CREATE_SUMMARY,
        ),
        TaskDefinition(
            "T4", "alice", "email-agent", frozenset({
                Grant(Permission(Action.READ, "email_inbox")),
                Grant(_SEND_MAIL, frozenset({"team@example.invalid"})),
            }),
            completion_effect=_SEND_MAIL, max_successful_sends=1,
        ),
        TaskDefinition("T5", "charlie", "document-agent", frozenset({Grant(_DELETE_SUMMARY)}), _DELETE_SUMMARY),
        TaskDefinition(
            "T6", "alice", "document-agent",
            frozenset({_READ_NOTES, Grant(Permission(Action.SEARCH, "meeting_notes.txt"))}),
        ),
    )
})
