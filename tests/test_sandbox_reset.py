import pytest

from agent_authz.sandbox import Fixture, SandboxEnvironment
from agent_authz.sandbox.fixtures import INBOX_DRAFT, initial_documents


@pytest.mark.parametrize("fixture", list(Fixture))
def test_reset_recovers_fixture_and_restarts_message_sequence(fixture):
    sandbox = SandboxEnvironment(fixture)
    initial = sandbox.snapshot()
    assert SandboxEnvironment(fixture).snapshot() == initial

    sandbox.edit_document("meeting_notes.txt", "Modified synthetic notes")
    sandbox.delete_document("public_report.txt")
    if fixture is Fixture.SUMMARY_ABSENT:
        sandbox.create_document("summary.txt", "Temporary summary")
    else:
        sandbox.delete_document("summary.txt")
    message = sandbox.send_simulated_email("email_outbox", "team@example.invalid", "Subject", "Body")
    assert message.message_id == 1
    assert sandbox.snapshot() != initial

    sandbox.reset()
    assert sandbox.snapshot() == initial
    sandbox.reset()
    assert sandbox.snapshot() == initial
    assert initial_documents(fixture) == initial.documents
    assert sandbox.read_email("email_inbox") == INBOX_DRAFT
    assert sandbox.send_simulated_email("email_outbox", "team@example.invalid", "Subject", "Body") == message


def test_instances_and_fixture_copies_do_not_share_mutable_state():
    first = SandboxEnvironment()
    second = SandboxEnvironment()
    original = second.snapshot()

    fixture_copy = initial_documents(Fixture.SUMMARY_ABSENT)
    fixture_copy["summary.txt"] = "Changed fixture copy"
    first.create_document("summary.txt", "First run summary")
    first.send_simulated_email("email_outbox", "team@example.invalid", "Subject", "Body")

    assert second.snapshot() == original
    assert SandboxEnvironment().snapshot() == original
    second.create_document("summary.txt", "Second run summary")
    assert first.read_document("summary.txt") == "First run summary"
    assert second.read_document("summary.txt") == "Second run summary"
    first.reset()
    assert first.snapshot() == original
    assert second.read_document("summary.txt") == "Second run summary"
