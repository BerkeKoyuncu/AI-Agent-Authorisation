"""Phase-one proof of concept; not the complete execution gateway."""

from collections.abc import Mapping
from dataclasses import dataclass

from .models import Action, AgentIdentity, ExecutionContext, Permission, TaskDelegation, ToolRequest, User


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def authorise(
    context: ExecutionContext,
    request: ToolRequest,
    *,
    users: Mapping[str, User],
    agents: Mapping[str, AgentIdentity],
    tasks: Mapping[str, TaskDelegation],
) -> Decision:
    """Evaluate exact action-resource pairs using trusted, synthetic records."""
    user = users.get(context.user_id)
    agent = agents.get(context.agent_id)
    task = tasks.get(context.task_id)

    if user is None or user.user_id != context.user_id:
        return Decision(False, "UNKNOWN_USER")
    if agent is None or agent.agent_id != context.agent_id:
        return Decision(False, "UNKNOWN_AGENT")
    if task is None or task.task_id != context.task_id or not task.active:
        return Decision(False, "INVALID_OR_INACTIVE_TASK")
    if (task.user_id, task.agent_id) != (context.user_id, context.agent_id):
        return Decision(False, "TASK_IDENTITY_MISMATCH")
    if not isinstance(request.action, Action) or not isinstance(request.resource_id, str) or not request.resource_id:
        return Decision(False, "INVALID_REQUEST")

    permission = Permission(request.action, request.resource_id)
    if permission not in user.permissions:
        return Decision(False, "USER_PERMISSION_DENIED")
    if permission not in agent.permissions:
        return Decision(False, "AGENT_PERMISSION_DENIED")
    if permission not in task.permissions:
        return Decision(False, "OUTSIDE_TASK_SCOPE")

    return Decision(True, "PERMISSION_GRANTED")
