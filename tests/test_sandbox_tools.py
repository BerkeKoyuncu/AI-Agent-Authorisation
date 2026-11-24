import pytest

from agent_authz.sandbox import ErrorCode, SandboxEnvironment, SandboxError
from agent_authz.sandbox.catalogue import RESOURCE_CATALOGUE
from agent_authz.sandbox.fixtures import INBOX_DRAFT


def test_document_read_and_search_leave_state_unchanged():
    sandbox = SandboxEnvironment()
    before = sandbox.snapshot()
    assert sandbox.read_document("meeting_notes.txt") == before.documents["meeting_notes.txt"]
    assert sandbox.search_documents("meeting_notes.txt", "agenda")
    assert sandbox.search_documents("meeting_notes.txt", "AGENDA") == ()
    assert sandbox.search_documents("meeting_notes.txt", "2400 lab credits") == ()
    assert sandbox.search_documents("financial_report.txt", "2400 lab credits")
    assert sandbox.snapshot() == before


def test_search_is_literal_and_retains_line_order():
    sandbox = SandboxEnvironment()
    sandbox.create_document("summary.txt", "first [.]\r\nsecond .\nthird [.]\nthird [.]\n")
    assert sandbox.search_documents("summary.txt", "[.]") == (
        "first [.]", "third [.]", "third [.]",
    )


def test_empty_document_exists_and_can_be_edited_and_deleted():
    sandbox = SandboxEnvironment()
    sandbox.create_document("summary.txt", "")
    assert sandbox.read_document("summary.txt") == ""
    assert sandbox.search_documents("summary.txt", "agenda") == ()

    before = sandbox.snapshot()
    with pytest.raises(SandboxError) as error:
        sandbox.create_document("summary.txt", "Duplicate")
    assert error.value.code is ErrorCode.DOCUMENT_EXISTS
    assert sandbox.snapshot() == before

    sandbox.edit_document("summary.txt", "Updated summary")
    assert sandbox.read_document("summary.txt") == "Updated summary"

    metadata = RESOURCE_CATALOGUE["summary.txt"]
    sandbox.delete_document("summary.txt")
    assert sandbox.snapshot().documents["summary.txt"] is None
    assert RESOURCE_CATALOGUE["summary.txt"] == metadata


@pytest.mark.parametrize(
    ("operation", "arguments"),
    [("read_document", ()), ("search_documents", ("agenda",)),
     ("edit_document", ("New content",)), ("delete_document", ())],
)
def test_absent_document_operations_preserve_state(operation, arguments):
    sandbox = SandboxEnvironment()
    sandbox.create_document("summary.txt", "Temporary content")
    sandbox.delete_document("summary.txt")
    before = sandbox.snapshot()

    with pytest.raises(SandboxError) as error:
        getattr(sandbox, operation)("summary.txt", *arguments)
    assert error.value.code is ErrorCode.DOCUMENT_MISSING
    assert sandbox.snapshot() == before


def test_document_creation_uses_slot_state_without_policy():
    sandbox = SandboxEnvironment()
    sandbox.delete_document("public_report.txt")
    sandbox.create_document("public_report.txt", "Replacement report")
    assert sandbox.read_document("public_report.txt") == "Replacement report"


def test_simulated_inbox_and_outbox_are_distinct_and_ordered():
    sandbox = SandboxEnvironment()
    before = sandbox.snapshot()
    assert sandbox.read_email("email_inbox") == INBOX_DRAFT
    assert sandbox.snapshot() == before

    destinations = ("team@example.invalid", "review@example.invalid", "team@example.invalid")
    messages = tuple(
        sandbox.send_simulated_email("email_outbox", route, "Synthetic subject", "Synthetic body")
        for route in destinations
    )
    after = sandbox.snapshot()
    assert after.outbox == messages
    assert tuple(message.destination for message in messages) == destinations
    assert tuple(message.message_id for message in messages) == (1, 2, 3)
    assert after.documents == before.documents
    assert after.inbox == before.inbox
