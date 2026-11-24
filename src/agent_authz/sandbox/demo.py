"""Demonstrate the trusted in-memory sandbox handlers."""

from . import SandboxEnvironment, SandboxError
from .fixtures import AGENDA_QUERY, EXPECTED_SUMMARY


def main() -> None:
    sandbox = SandboxEnvironment()
    print(f"Trusted sandbox demonstration | {sandbox.snapshot().fixture}")

    notes = sandbox.read_document("meeting_notes.txt")
    print(f"Read meeting_notes.txt: {len(notes.splitlines())} lines")
    (match,) = sandbox.search_documents("meeting_notes.txt", AGENDA_QUERY)
    print(f"Search for {AGENDA_QUERY}: {match}")

    sandbox.create_document("summary.txt", EXPECTED_SUMMARY)
    print("Created summary.txt")
    sandbox.edit_document("summary.txt", f"{EXPECTED_SUMMARY} Draft reviewed.")
    print("Edited summary.txt")

    draft = sandbox.read_email("email_inbox")
    print(f"Read simulated inbox: {draft.subject}")
    message = sandbox.send_simulated_email("email_outbox", draft.destination, draft.subject, draft.body)
    print(f"Appended simulated message {message.message_id} to {message.destination}")

    sandbox.delete_document("summary.txt")
    print("Deleted summary.txt content")

    try:
        sandbox.read_document("unregistered.txt")
    except SandboxError as error:
        print(f"Invalid logical identifier rejected: {error.code}")

    sandbox.reset()
    snapshot = sandbox.snapshot()
    status = "absent" if snapshot.documents["summary.txt"] is None else "present"
    print(f"Reset to {snapshot.fixture}: summary slot {status}, {len(snapshot.outbox)} outbox messages")


if __name__ == "__main__":
    main()
