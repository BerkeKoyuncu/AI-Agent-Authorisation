"""Initial domain models for identity and task delegation."""

from dataclasses import dataclass
from enum import StrEnum


class Action(StrEnum):
    READ = "read"
    CREATE = "create"


@dataclass(frozen=True)
class Permission:
    action: Action
    resource_id: str


@dataclass(frozen=True)
class User:
    user_id: str
    permissions: frozenset[Permission]


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    permissions: frozenset[Permission]


@dataclass(frozen=True)
class TaskDelegation:
    task_id: str
    user_id: str
    agent_id: str
    permissions: frozenset[Permission]
    active: bool = True


@dataclass(frozen=True)
class ExecutionContext:
    """Identifiers supplied by the trusted runner, never by model arguments."""

    user_id: str
    agent_id: str
    task_id: str


@dataclass(frozen=True)
class ToolRequest:
    """An untrusted action request; carries no identity or delegated authority."""

    action: Action
    resource_id: str
