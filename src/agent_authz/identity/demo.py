"""Demonstrate trusted synthetic identity and delegation binding."""

from dataclasses import replace

from ..delegation import DelegationManager
from .errors import AuthorityError
from .principals import IdentityStore
from .sessions import SessionManager


def main() -> None:
    sessions = SessionManager(IdentityStore())
    delegations = DelegationManager(sessions)
    print("Trusted identity and delegation demonstration (no tools executed)")

    proof = sessions.provision_credential("alice")
    token = sessions.authenticate("alice", proof)
    print(f"Authenticated {sessions.validate_session(token).human_id} and established a synthetic session")
    run = sessions.start_run(token, "document-agent")
    print(f"Assigned {run.agent_id} to a trusted run")

    pending = delegations.issue(run, "T1")
    print(f"Issued {pending.task_id} delegation for the registered run ({pending.status})")
    active = delegations.activate(run, pending.delegation_id)
    context = delegations.bind_context(run, active.delegation_id)
    authority = delegations.validate_task_authority(context)
    print(f"Established execution context for {context.task_id} ({authority.status})")
    for grant in sorted(authority.grants, key=lambda item: (item.permission.action, item.permission.resource_id)):
        print(f"Delegated grant: {grant.permission.action} {grant.permission.resource_id}")

    try:
        delegations.validate_task_authority(replace(context, task_id="T2"))
    except AuthorityError as error:
        print(f"Mismatched context rejected: {error.code}")

    revoked = delegations.revoke(active.delegation_id)
    print(f"Updated delegation to {revoked.status}")
    try:
        delegations.validate_task_authority(context)
    except AuthorityError as error:
        print(f"Task authority rejected: {error.code}")
    sessions.validate_run(run)
    print("Shared session and run binding still valid")


if __name__ == "__main__":
    main()
