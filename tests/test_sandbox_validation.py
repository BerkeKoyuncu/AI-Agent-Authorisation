import builtins
import io
import os
import smtplib
import socket

import pytest

from agent_authz.sandbox import ErrorCode, SandboxEnvironment, SandboxError
from agent_authz.sandbox.environment import (
    MAX_BODY_LENGTH,
    MAX_DOCUMENT_LENGTH,
    MAX_QUERY_LENGTH,
    MAX_SUBJECT_LENGTH,
)

TEAM = "team@example.invalid"


@pytest.fixture
def io_guard(monkeypatch):
    def unexpected_io(*args, **kwargs):
        pytest.fail("Sandbox handlers must not use host file or network APIs")

    with monkeypatch.context() as guard:
        for module, name in (
            (builtins, "open"), (io, "open"), (os, "open"), (os, "unlink"),
            (os, "remove"), (socket, "socket"), (socket, "create_connection"),
            (socket, "getaddrinfo"), (smtplib, "SMTP"), (smtplib, "SMTP_SSL"),
        ):
            guard.setattr(module, name, unexpected_io)
        yield


@pytest.mark.parametrize("resource_id", [
    "../../.env", "/etc/passwd", r"C:\Windows\System32", "https://example.invalid/document",
    "", "*.txt", " meeting_notes.txt ", "unregistered.txt", "./meeting_notes.txt",
    "MEETING_NOTES.TXT",
])
def test_unregistered_ids_are_inert_in_every_handler(resource_id, io_guard):
    sandbox = SandboxEnvironment()
    before = sandbox.snapshot()
    calls = (
        (sandbox.read_document, ()), (sandbox.search_documents, ("agenda",)),
        (sandbox.create_document, ("New content",)), (sandbox.edit_document, ("New content",)),
        (sandbox.delete_document, ()), (sandbox.read_email, ()),
        (sandbox.send_simulated_email, (TEAM, "Subject", "Body")),
    )
    for handler, arguments in calls:
        with pytest.raises(SandboxError) as error:
            handler(resource_id, *arguments)
        assert error.value.code is ErrorCode.UNKNOWN_RESOURCE
        assert str(error.value) == "The resource identifier is not registered."
        assert sandbox.snapshot() == before


def test_valid_mutations_and_simulated_email_use_no_host_io(io_guard):
    sandbox = SandboxEnvironment()
    sandbox.create_document("summary.txt", "One line")
    sandbox.edit_document("summary.txt", "Updated")
    assert sandbox.search_documents("summary.txt", "Updated") == ("Updated",)
    sandbox.delete_document("summary.txt")
    draft = sandbox.read_email("email_inbox")
    message = sandbox.send_simulated_email("email_outbox", draft.destination, draft.subject, draft.body)
    assert sandbox.snapshot().outbox == (message,)


@pytest.mark.parametrize(("operation", "arguments"), [
    ("read_document", ("email_inbox",)),
    ("search_documents", ("email_outbox", "agenda")),
    ("create_document", ("email_inbox", "content")),
    ("edit_document", ("email_outbox", "content")),
    ("delete_document", ("email_inbox",)),
    ("read_email", ("meeting_notes.txt",)),
    ("read_email", ("email_outbox",)),
    ("send_simulated_email", ("summary.txt", TEAM, "Subject", "Body")),
    ("send_simulated_email", ("email_inbox", TEAM, "Subject", "Body")),
])
def test_resource_kind_mismatch_does_not_change_state(operation, arguments):
    sandbox = SandboxEnvironment()
    before = sandbox.snapshot()
    with pytest.raises(SandboxError) as error:
        getattr(sandbox, operation)(*arguments)
    assert error.value.code is ErrorCode.RESOURCE_KIND_MISMATCH
    assert sandbox.snapshot() == before


class StringSubclass(str):
    pass


@pytest.mark.parametrize(("operation", "arguments"), [
    ("read_document", (b"meeting_notes.txt",)),
    ("read_document", (StringSubclass("meeting_notes.txt"),)),
    ("search_documents", ("meeting_notes.txt", 5)),
    ("search_documents", ("meeting_notes.txt", "")),
    ("create_document", ("summary.txt", None)),
    ("edit_document", ("meeting_notes.txt", ["Replacement"])),
    ("delete_document", ([],)),
    ("read_email", (None,)),
    ("send_simulated_email", ("email_outbox", [TEAM], "Subject", "Body")),
    ("send_simulated_email", ("email_outbox", TEAM, 1, "Body")),
    ("send_simulated_email", ("email_outbox", TEAM, "Subject", b"Body")),
])
def test_invalid_argument_types_and_empty_query_are_rejected(operation, arguments):
    sandbox = SandboxEnvironment()
    before = sandbox.snapshot()
    with pytest.raises(SandboxError) as error:
        getattr(sandbox, operation)(*arguments)
    assert error.value.code is ErrorCode.INVALID_ARGUMENT
    assert sandbox.snapshot() == before


@pytest.mark.parametrize("destination", ["", "other@example.invalid", f" {TEAM}", TEAM.upper()])
def test_destinations_are_exact_without_consuming_message_ids(destination):
    sandbox = SandboxEnvironment()
    before = sandbox.snapshot()
    with pytest.raises(SandboxError) as error:
        sandbox.send_simulated_email("email_outbox", destination, "Subject", "Body")
    assert error.value.code is ErrorCode.INVALID_DESTINATION
    assert sandbox.snapshot() == before
    assert sandbox.send_simulated_email("email_outbox", TEAM, "", "").message_id == 1


def test_maximum_lengths_are_inclusive_and_count_unicode_code_points():
    sandbox = SandboxEnvironment()
    query = "é" * MAX_QUERY_LENGTH
    content = "é" * MAX_DOCUMENT_LENGTH
    sandbox.create_document("summary.txt", content)
    assert sandbox.search_documents("summary.txt", query) == (content,)

    replacement = "Ω" * MAX_DOCUMENT_LENGTH
    sandbox.edit_document("summary.txt", replacement)
    assert sandbox.read_document("summary.txt") == replacement

    subject = "é" * MAX_SUBJECT_LENGTH
    body = "Ω" * MAX_BODY_LENGTH
    message = sandbox.send_simulated_email("email_outbox", TEAM, subject, body)
    assert (message.subject, message.body) == (subject, body)


@pytest.mark.parametrize(("operation", "arguments"), [
    ("search_documents", ("meeting_notes.txt", "a" * (MAX_QUERY_LENGTH + 1))),
    ("create_document", ("summary.txt", "a" * (MAX_DOCUMENT_LENGTH + 1))),
    ("edit_document", ("meeting_notes.txt", "a" * (MAX_DOCUMENT_LENGTH + 1))),
    ("send_simulated_email", ("email_outbox", TEAM, "a" * (MAX_SUBJECT_LENGTH + 1), "Body")),
    ("send_simulated_email", ("email_outbox", TEAM, "Subject", "a" * (MAX_BODY_LENGTH + 1))),
])
def test_oversized_arguments_preserve_state(operation, arguments):
    sandbox = SandboxEnvironment()
    before = sandbox.snapshot()
    with pytest.raises(SandboxError) as error:
        getattr(sandbox, operation)(*arguments)
    assert error.value.code is ErrorCode.INVALID_ARGUMENT
    assert sandbox.snapshot() == before
