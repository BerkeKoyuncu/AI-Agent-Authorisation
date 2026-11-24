from dataclasses import FrozenInstanceError

import pytest

from agent_authz.sandbox import ErrorCode, Fixture, SandboxEnvironment, SandboxError
from agent_authz.sandbox.catalogue import RESOURCE_CATALOGUE
from agent_authz.sandbox.fixtures import (
    AGENDA_LINE,
    AGENDA_QUERY,
    EXPECTED_SUMMARY,
    FINANCIAL_FACTS,
    INBOX_DRAFT,
    MEETING_FACTS,
    SEEDED_SUMMARY,
)


def test_catalogue_matches_access_control_design():
    metadata = {
        resource_id: (resource.kind, resource.classification, resource.owner_id)
        for resource_id, resource in RESOURCE_CATALOGUE.items()
    }
    assert metadata == {
        "meeting_notes.txt": ("document", "Internal", "alice"),
        "public_report.txt": ("document", "Public", "bob"),
        "financial_report.txt": ("document", "Confidential", "bob"),
        "salary_data.txt": ("document", "Restricted", "charlie"),
        "summary.txt": ("document", "Internal", "alice"),
        "email_inbox": ("inbox", "Internal", "alice"),
        "email_outbox": ("outbox", "Internal", "alice"),
    }
    assert all(resource_id == resource.resource_id for resource_id, resource in RESOURCE_CATALOGUE.items())
    assert set(SandboxEnvironment().snapshot().documents) == {
        resource_id for resource_id, (kind, _, _) in metadata.items() if kind == "document"
    }


def test_catalogue_metadata_is_read_only():
    metadata = RESOURCE_CATALOGUE["summary.txt"]
    with pytest.raises(TypeError):
        RESOURCE_CATALOGUE["unregistered.txt"] = metadata
    with pytest.raises(FrozenInstanceError):
        metadata.owner_id = "bob"


def test_fixture_variants_differ_only_by_initial_summary():
    creation = SandboxEnvironment().snapshot()
    deletion = SandboxEnvironment(Fixture.SUMMARY_SEEDED).snapshot()

    assert creation.fixture.value == "enterprise-v1-summary-absent"
    assert deletion.fixture.value == "enterprise-v1-summary-seeded"
    assert creation.documents["summary.txt"] is None
    assert deletion.documents == {**creation.documents, "summary.txt": SEEDED_SUMMARY}
    assert creation.inbox == deletion.inbox == INBOX_DRAFT
    assert creation.outbox == deletion.outbox == ()


def test_unknown_fixture_is_rejected_without_coercion():
    with pytest.raises(SandboxError) as error:
        SandboxEnvironment(Fixture.SUMMARY_ABSENT.value)
    assert error.value.code is ErrorCode.INVALID_ARGUMENT


def test_reference_inputs_and_effects_support_all_six_normal_cases():
    sandbox = SandboxEnvironment()
    notes = sandbox.read_document("meeting_notes.txt")
    report = sandbox.read_document("financial_report.txt")
    assert all(fact in notes for fact in MEETING_FACTS)  # T1
    assert all(fact in report for fact in FINANCIAL_FACTS)  # T2

    sandbox.create_document("summary.txt", EXPECTED_SUMMARY)  # T3
    assert sandbox.snapshot().documents["summary.txt"] == EXPECTED_SUMMARY

    draft = sandbox.read_email("email_inbox")  # T4
    sandbox.send_simulated_email("email_outbox", draft.destination, draft.subject, draft.body)
    (message,) = sandbox.snapshot().outbox
    assert (message.destination, message.subject, message.body) == (
        "team@example.invalid", INBOX_DRAFT.subject, INBOX_DRAFT.body,
    )

    sandbox = SandboxEnvironment(Fixture.SUMMARY_SEEDED)
    before_delete = sandbox.snapshot()
    sandbox.delete_document("summary.txt")  # T5
    after_delete = sandbox.snapshot()
    assert after_delete.documents == {**before_delete.documents, "summary.txt": None}
    assert after_delete.inbox == before_delete.inbox
    assert after_delete.outbox == before_delete.outbox

    assert sandbox.search_documents("meeting_notes.txt", AGENDA_QUERY) == (AGENDA_LINE,)  # T6


def test_snapshot_is_immutable_and_detached_from_subsequent_changes():
    sandbox = SandboxEnvironment()
    message = sandbox.send_simulated_email("email_outbox", "team@example.invalid", "Subject", "Body")
    snapshot = sandbox.snapshot()

    with pytest.raises(TypeError):
        snapshot.documents["summary.txt"] = "Replacement"
    with pytest.raises(FrozenInstanceError):
        snapshot.inbox.body = "Replacement"
    with pytest.raises(FrozenInstanceError):
        message.destination = "review@example.invalid"
    with pytest.raises(FrozenInstanceError):
        snapshot.outbox = ()

    sandbox.create_document("summary.txt", "New summary")
    sandbox.send_simulated_email("email_outbox", "team@example.invalid", "Another subject", "Another body")
    assert snapshot.documents["summary.txt"] is None
    assert snapshot.outbox == (message,)
