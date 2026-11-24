"""Run a minimal, synthetic authorisation demonstration."""

from .models import Action, AgentIdentity, ExecutionContext, Permission, TaskDelegation, ToolRequest, User
from .policy import authorise


def main() -> None:
    meeting = Permission(Action.READ, "meeting_notes.txt")
    salary = Permission(Action.READ, "salary_data.txt")
    permissions = frozenset({meeting, salary})
    user = User("user_002", permissions)
    agent = AgentIdentity("agent_001", permissions)
    task = TaskDelegation("task_001", user.user_id, agent.agent_id, frozenset({meeting}))
    context = ExecutionContext(user.user_id, agent.agent_id, task.task_id)

    print("Synthetic authorisation demo (no tools executed)")
    print(f"User: {context.user_id} | Agent: {context.agent_id} | Task: {context.task_id}")
    for resource in ("meeting_notes.txt", "salary_data.txt"):
        request = ToolRequest(Action.READ, resource)
        decision = authorise(
            context, request,
            users={user.user_id: user},
            agents={agent.agent_id: agent},
            tasks={task.task_id: task},
        )
        verdict = "ALLOW" if decision.allowed else "DENY"
        print(f"{request.action.value} {resource}: {verdict} ({decision.reason})")


if __name__ == "__main__":
    main()
