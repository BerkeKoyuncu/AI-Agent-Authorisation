"""Compare the gateway policies using only synthetic local effects."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from ..delegation import DelegationManager, RuntimeExecutionContext
from ..identity.principals import IdentityStore
from ..identity.sessions import RunBinding, SessionManager
from ..sandbox.environment import SandboxEnvironment
from ..sandbox.fixtures import INBOX_DRAFT
from . import Gateway, PolicyMode
from .audit import JsonlAudit
from .models import GatewayResult


def _show(label: str, result: GatewayResult) -> None:
    verdict = "allow" if result.decision.allowed else "deny"
    print(f"  {label}: {verdict} ({result.decision.reason}), execution={result.execution}")


def _run_mode(mode: PolicyMode, path: Path) -> None:
    identities = IdentityStore()
    sessions = SessionManager(identities)
    delegations = DelegationManager(sessions)
    sandbox = SandboxEnvironment()
    gateway = Gateway(mode, sessions, delegations, sandbox, JsonlAudit(path))
    proof = sessions.provision_credential("alice")
    token = sessions.authenticate("alice", proof)

    def bind(agent: str, task_id: str) -> tuple[RunBinding, RuntimeExecutionContext]:
        run = sessions.start_run(token, agent)
        pending = delegations.issue(run, task_id)
        delegations.activate(run, pending.delegation_id)
        return run, delegations.bind_context(run, pending.delegation_id)

    documents, doc_context = bind("document-agent", "T1")
    notes = {"tool": "read_document", "arguments": {"resource_id": "meeting_notes.txt"}}
    print(f"System {mode}")
    _show("Meeting-note read", gateway.handle(notes, documents, doc_context))
    _show("Out-of-scope public-report read", gateway.handle(
        {"tool": "read_document", "arguments": {"resource_id": "public_report.txt"}}, documents, doc_context,
    ))
    _show("Authority override", gateway.handle({**notes, "user_id": "charlie"}, documents, doc_context))

    mail, mail_context = bind("email-agent", "T4")

    def send(destination: str) -> GatewayResult:
        return gateway.handle({"tool": "send_simulated_email", "arguments": {
            "resource_id": "email_outbox", "destination": destination,
            "subject": INBOX_DRAFT.subject, "body": INBOX_DRAFT.body,
        }}, mail, mail_context)

    before_review = sandbox.snapshot()
    review = send("review@example.invalid")
    _show("Review route", review)
    if not review.dispatched:
        assert sandbox.snapshot() == before_review
        print("  Review denial preserved the sandbox snapshot")
    first = send(INBOX_DRAFT.destination)
    _show("Team route", first)
    before_repeat = sandbox.snapshot()
    repeat = send(INBOX_DRAFT.destination)
    _show("Repeat team send", repeat)
    if not repeat.dispatched:
        assert sandbox.snapshot() == before_repeat
        print("  Repeat denial preserved the sandbox snapshot")
    print(f"  Outbox messages: {len(sandbox.snapshot().outbox)}")

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    correlated = [entry for entry in records if entry["request_id"] == first.request_id]
    phases = ", ".join(entry["event"] for entry in correlated)
    print(f"  Correlated team-send audit events: {phases}")


def main() -> None:
    print("Trusted gateway demonstration (synthetic sandbox)")
    with TemporaryDirectory(prefix="agent-authz-gateway-") as directory:
        for mode in PolicyMode:
            _run_mode(mode, Path(directory) / f"system-{mode}.jsonl")


if __name__ == "__main__":
    main()
