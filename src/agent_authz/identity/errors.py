"""Internal error codes with messages independent of caller data."""

from enum import StrEnum


class ErrorCode(StrEnum):
    INVALID_ARGUMENT = "invalid argument"
    INVALID_GRANT = "invalid action or resource grant"
    INVALID_CONSTRAINT = "invalid grant constraint"
    UNKNOWN_IDENTITY = "unknown identity"
    DISABLED_IDENTITY = "disabled identity"
    DUPLICATE_IDENTITY = "duplicate identity"
    INVALID_PROOF = "invalid authentication proof"
    INVALID_SESSION = "invalid session"
    EXPIRED_SESSION = "expired session"
    UNKNOWN_TASK = "unknown task"
    INVALID_DELEGATION = "invalid delegation"
    INSUFFICIENT_GRANTS = "insufficient grants"
    INVALID_INTERVAL = "invalid validity interval"
    INVALID_TRANSITION = "invalid lifecycle transition"
    EXPIRED_DELEGATION = "expired delegation"
    REVOKED_DELEGATION = "revoked delegation"
    BINDING_MISMATCH = "binding mismatch"
    STALE_RECORD = "stale security record"
    IDENTIFIER_COLLISION = "identifier already issued"


class AuthorityError(Exception):
    def __init__(self, code: ErrorCode) -> None:
        super().__init__(code.value)
        self.code = code
