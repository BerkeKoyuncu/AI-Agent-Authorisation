"""Own sandbox state and execute the seven trusted tool handlers."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .catalogue import ResourceKind, resolve_resource
from .errors import ErrorCode, SandboxError
from .fixtures import INBOX_DRAFT, EmailDraft, Fixture, initial_documents

MAX_QUERY_LENGTH = 256
MAX_DOCUMENT_LENGTH = 16_384
MAX_SUBJECT_LENGTH = 256
MAX_BODY_LENGTH = 16_384
SIMULATOR_DESTINATIONS = frozenset({"team@example.invalid", "review@example.invalid"})


@dataclass(frozen=True, slots=True)
class OutboxMessage:
    message_id: int
    destination: str
    subject: str
    body: str


@dataclass(frozen=True, slots=True)
class SandboxSnapshot:
    fixture: Fixture
    documents: Mapping[str, str | None]
    inbox: EmailDraft
    outbox: tuple[OutboxMessage, ...]


def _validate_text(value: str, maximum: int, *, minimum: int = 0) -> None:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise SandboxError(ErrorCode.INVALID_ARGUMENT)


class SandboxEnvironment:
    """Single-threaded state owned by trusted callers for one sandbox run."""

    def __init__(self, fixture: Fixture = Fixture.SUMMARY_ABSENT) -> None:
        self._fixture = fixture
        self._documents: dict[str, str | None]
        self._inbox: EmailDraft
        self._outbox: list[OutboxMessage]
        self.reset()

    def reset(self) -> None:
        """Restore the fixture's documents, fixed inbox draft and empty outbox."""
        self._documents = initial_documents(self._fixture)
        self._inbox = INBOX_DRAFT
        self._outbox = []

    def snapshot(self) -> SandboxSnapshot:
        """Take an immutable observation without borrowing mutable sandbox state."""
        return SandboxSnapshot(
            fixture=self._fixture,
            documents=MappingProxyType(self._documents.copy()),
            inbox=self._inbox,
            outbox=tuple(self._outbox),
        )

    def read_document(self, resource_id: str) -> str:
        resolve_resource(resource_id, ResourceKind.DOCUMENT)
        content = self._documents[resource_id]
        if content is None:
            raise SandboxError(ErrorCode.DOCUMENT_MISSING)
        return content

    def search_documents(self, resource_id: str, query: str) -> tuple[str, ...]:
        """Find case-sensitive literal matches in the named document only."""
        _validate_text(query, MAX_QUERY_LENGTH, minimum=1)
        content = self.read_document(resource_id)
        return tuple(line for line in content.splitlines() if query in line)

    def create_document(self, resource_id: str, content: str) -> None:
        resolve_resource(resource_id, ResourceKind.DOCUMENT)
        _validate_text(content, MAX_DOCUMENT_LENGTH)
        if self._documents[resource_id] is not None:
            raise SandboxError(ErrorCode.DOCUMENT_EXISTS)
        self._documents[resource_id] = content

    def edit_document(self, resource_id: str, content: str) -> None:
        self.read_document(resource_id)
        _validate_text(content, MAX_DOCUMENT_LENGTH)
        self._documents[resource_id] = content

    def delete_document(self, resource_id: str) -> None:
        self.read_document(resource_id)
        self._documents[resource_id] = None

    def read_email(self, resource_id: str) -> EmailDraft:
        resolve_resource(resource_id, ResourceKind.INBOX)
        return self._inbox

    def send_simulated_email(
        self, resource_id: str, destination: str, subject: str, body: str
    ) -> OutboxMessage:
        resolve_resource(resource_id, ResourceKind.OUTBOX)
        if type(destination) is not str:
            raise SandboxError(ErrorCode.INVALID_ARGUMENT)
        if destination not in SIMULATOR_DESTINATIONS:
            raise SandboxError(ErrorCode.INVALID_DESTINATION)
        _validate_text(subject, MAX_SUBJECT_LENGTH)
        _validate_text(body, MAX_BODY_LENGTH)
        message = OutboxMessage(len(self._outbox) + 1, destination, subject, body)
        self._outbox.append(message)
        return message
