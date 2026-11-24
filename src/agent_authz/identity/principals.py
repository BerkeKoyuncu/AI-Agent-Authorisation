"""Versioned human and agent records managed by trusted callers."""

from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import StrEnum

from ..models import Action, Permission
from ..sandbox.environment import SIMULATOR_DESTINATIONS
from .errors import AuthorityError, ErrorCode
from .grants import Grant, validate_grants


class PrincipalKind(StrEnum):
    HUMAN = "human"
    AGENT = "agent"


@dataclass(frozen=True, slots=True)
class Principal:
    kind: PrincipalKind
    principal_id: str
    label: str
    grants: frozenset[Grant]
    enabled: bool = True
    version: int = 1

    def __post_init__(self) -> None:
        if (type(self.kind) is not PrincipalKind or type(self.principal_id) is not str
                or not self.principal_id or type(self.label) is not str or not self.label
                or type(self.enabled) is not bool or type(self.version) is not int or self.version < 1):
            raise AuthorityError(ErrorCode.INVALID_ARGUMENT)
        validate_grants(self.grants)


_MEETING_READ = Grant(Permission(Action.READ, "meeting_notes.txt"))
_MEETING_SEARCH = Grant(Permission(Action.SEARCH, "meeting_notes.txt"))
_PUBLIC_READ = Grant(Permission(Action.READ, "public_report.txt"))
_PUBLIC_SEARCH = Grant(Permission(Action.SEARCH, "public_report.txt"))
_PUBLIC_EDIT = Grant(Permission(Action.EDIT, "public_report.txt"))
_FINANCIAL_READ = Grant(Permission(Action.READ, "financial_report.txt"))
_FINANCIAL_SEARCH = Grant(Permission(Action.SEARCH, "financial_report.txt"))
_SALARY_READ = Grant(Permission(Action.READ, "salary_data.txt"))
_SALARY_SEARCH = Grant(Permission(Action.SEARCH, "salary_data.txt"))
_SUMMARY_READ = Grant(Permission(Action.READ, "summary.txt"))
_SUMMARY_CREATE = Grant(Permission(Action.CREATE, "summary.txt"))
_SUMMARY_DELETE = Grant(Permission(Action.DELETE, "summary.txt"))
_INBOX_READ = Grant(Permission(Action.READ, "email_inbox"))
_OUTBOX_SEND = Grant(Permission(Action.SEND, "email_outbox"), SIMULATOR_DESTINATIONS)

_COMMON_DOCUMENTS = frozenset({_MEETING_READ, _MEETING_SEARCH, _PUBLIC_READ, _PUBLIC_SEARCH})
_FINANCIAL_DOCUMENT = frozenset({_FINANCIAL_READ, _FINANCIAL_SEARCH})
_SUMMARY_READ_CREATE = frozenset({_SUMMARY_READ, _SUMMARY_CREATE})
_MAIL = frozenset({_INBOX_READ, _OUTBOX_SEND})
PRINCIPAL_FIXTURES = (
    Principal(PrincipalKind.HUMAN, "alice", "Employee", _COMMON_DOCUMENTS | _SUMMARY_READ_CREATE | _MAIL),
    Principal(PrincipalKind.HUMAN, "bob", "Manager", _COMMON_DOCUMENTS | _FINANCIAL_DOCUMENT | {_PUBLIC_EDIT}),
    Principal(
        PrincipalKind.HUMAN, "charlie", "Administrator",
        _COMMON_DOCUMENTS | _FINANCIAL_DOCUMENT | {_SALARY_READ, _SALARY_SEARCH, _SUMMARY_READ, _SUMMARY_DELETE},
    ),
    Principal(
        PrincipalKind.AGENT, "document-agent", "Document Agent",
        _COMMON_DOCUMENTS | _FINANCIAL_DOCUMENT | _SUMMARY_READ_CREATE | {_PUBLIC_EDIT, _SUMMARY_DELETE},
    ),
    Principal(PrincipalKind.AGENT, "email-agent", "Email Agent", _MAIL),
)


class IdentityStore:
    """Keep independent human and agent namespaces in an in-memory store."""

    def __init__(self, principals: Iterable[Principal] = PRINCIPAL_FIXTURES) -> None:
        self._records: dict[tuple[PrincipalKind, str], Principal] = {}
        for principal in principals:
            if type(principal) is not Principal:
                raise AuthorityError(ErrorCode.INVALID_ARGUMENT)
            key = (principal.kind, principal.principal_id)
            if key in self._records:
                raise AuthorityError(ErrorCode.DUPLICATE_IDENTITY)
            self._records[key] = principal

    def lookup(self, kind: PrincipalKind, principal_id: str, *, expected_version: int | None = None) -> Principal:
        if type(kind) is not PrincipalKind or type(principal_id) is not str:
            raise AuthorityError(ErrorCode.INVALID_ARGUMENT)
        record = self._records.get((kind, principal_id))
        if record is None:
            raise AuthorityError(ErrorCode.UNKNOWN_IDENTITY)
        if expected_version is not None and (type(expected_version) is not int or expected_version != record.version):
            raise AuthorityError(ErrorCode.STALE_RECORD)
        return record

    def require_enabled(self, kind: PrincipalKind, principal_id: str) -> Principal:
        record = self.lookup(kind, principal_id)
        if not record.enabled:
            raise AuthorityError(ErrorCode.DISABLED_IDENTITY)
        return record

    def replace_grants(self, kind: PrincipalKind, principal_id: str, grants: frozenset[Grant]) -> Principal:
        record = self.lookup(kind, principal_id)
        updated = replace(record, grants=grants, version=record.version + 1)
        self._records[kind, principal_id] = updated
        return updated

    def disable(self, kind: PrincipalKind, principal_id: str) -> Principal:
        record = self.require_enabled(kind, principal_id)
        updated = replace(record, enabled=False, version=record.version + 1)
        self._records[kind, principal_id] = updated
        return updated
