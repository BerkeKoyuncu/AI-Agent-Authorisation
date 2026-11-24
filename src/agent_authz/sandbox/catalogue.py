"""Fixed logical resource identifiers and descriptive metadata."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from .errors import ErrorCode, SandboxError


class ResourceKind(StrEnum):
    DOCUMENT = "document"
    INBOX = "inbox"
    OUTBOX = "outbox"


class Classification(StrEnum):
    INTERNAL = "Internal"
    PUBLIC = "Public"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"


@dataclass(frozen=True, slots=True)
class ResourceMetadata:
    resource_id: str
    kind: ResourceKind
    classification: Classification
    owner_id: str


RESOURCE_CATALOGUE: Mapping[str, ResourceMetadata] = MappingProxyType({
    resource.resource_id: resource
    for resource in (
        ResourceMetadata("meeting_notes.txt", ResourceKind.DOCUMENT, Classification.INTERNAL, "alice"),
        ResourceMetadata("public_report.txt", ResourceKind.DOCUMENT, Classification.PUBLIC, "bob"),
        ResourceMetadata("financial_report.txt", ResourceKind.DOCUMENT, Classification.CONFIDENTIAL, "bob"),
        ResourceMetadata("salary_data.txt", ResourceKind.DOCUMENT, Classification.RESTRICTED, "charlie"),
        ResourceMetadata("summary.txt", ResourceKind.DOCUMENT, Classification.INTERNAL, "alice"),
        ResourceMetadata("email_inbox", ResourceKind.INBOX, Classification.INTERNAL, "alice"),
        ResourceMetadata("email_outbox", ResourceKind.OUTBOX, Classification.INTERNAL, "alice"),
    )
})


def resolve_resource(resource_id: str, expected_kind: ResourceKind) -> ResourceMetadata:
    """Resolve one exact identifier without interpreting it as a path or route."""
    if type(resource_id) is not str:
        raise SandboxError(ErrorCode.INVALID_ARGUMENT)
    resource = RESOURCE_CATALOGUE.get(resource_id)
    if resource is None:
        raise SandboxError(ErrorCode.UNKNOWN_RESOURCE)
    if resource.kind is not expected_kind:
        raise SandboxError(ErrorCode.RESOURCE_KIND_MISMATCH)
    return resource
