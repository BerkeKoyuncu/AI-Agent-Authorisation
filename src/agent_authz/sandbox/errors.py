"""Structured sandbox errors with safe, fixed messages."""

from enum import StrEnum


class ErrorCode(StrEnum):
    UNKNOWN_RESOURCE = "UNKNOWN_RESOURCE"
    RESOURCE_KIND_MISMATCH = "RESOURCE_KIND_MISMATCH"
    DOCUMENT_MISSING = "DOCUMENT_MISSING"
    DOCUMENT_EXISTS = "DOCUMENT_EXISTS"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INVALID_DESTINATION = "INVALID_DESTINATION"


_MESSAGES = {
    ErrorCode.UNKNOWN_RESOURCE: "The resource identifier is not registered.",
    ErrorCode.RESOURCE_KIND_MISMATCH: "The resource kind does not match the operation.",
    ErrorCode.DOCUMENT_MISSING: "The document slot has no content.",
    ErrorCode.DOCUMENT_EXISTS: "The document slot already has content.",
    ErrorCode.INVALID_ARGUMENT: "An argument is invalid.",
    ErrorCode.INVALID_DESTINATION: "The simulator destination is not registered.",
}


class SandboxError(Exception):
    """Report an internal validation or precondition failure."""

    def __init__(self, code: ErrorCode) -> None:
        super().__init__(_MESSAGES[code])
        self.code = code
