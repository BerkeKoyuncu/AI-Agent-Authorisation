"""Synthetic authentication and shared session/run binding."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from secrets import compare_digest, token_urlsafe

from .errors import AuthorityError, ErrorCode
from .principals import IdentityStore, PrincipalKind


SESSION_DURATION = timedelta(minutes=30)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def require_utc(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is not timezone.utc or value.fold:
        raise AuthorityError(ErrorCode.INVALID_INTERVAL)
    return value


def expires_after(start: datetime, duration: timedelta) -> datetime:
    try:
        return start + duration
    except OverflowError:
        raise AuthorityError(ErrorCode.INVALID_INTERVAL) from None


def opaque_identifier() -> str:
    return token_urlsafe(32)


def _digest(value: str, error: ErrorCode) -> bytes:
    if type(value) is not str or not 1 <= len(value) <= 256 or not value.isascii():
        raise AuthorityError(error)
    return sha256(value.encode("ascii")).digest()


@dataclass(frozen=True, slots=True)
class Session:
    session_id: str
    human_id: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RunBinding:
    run_id: str
    session_id: str
    human_id: str
    agent_id: str


class SessionManager:
    """Own registered sessions and runs independently of task delegations."""

    def __init__(
        self,
        identities: IdentityStore,
        *,
        clock: Callable[[], datetime] = utc_now,
        new_id: Callable[[], str] = opaque_identifier,
    ) -> None:
        self._identities = identities
        self._clock = clock
        self._new_id = new_id
        self._issued_ids: set[bytes] = set()
        self._proofs: dict[str, bytes] = {}
        self._token_sessions: dict[bytes, str] = {}
        self._sessions: dict[str, Session] = {}
        self._runs: dict[str, RunBinding] = {}

    @property
    def identities(self) -> IdentityStore:
        return self._identities

    def now(self) -> datetime:
        return require_utc(self._clock())

    def _mint(self) -> tuple[str, bytes]:
        value = self._new_id()
        digest = _digest(value, ErrorCode.INVALID_ARGUMENT)
        if digest in self._issued_ids:
            raise AuthorityError(ErrorCode.IDENTIFIER_COLLISION)
        self._issued_ids.add(digest)
        return value, digest

    def provision_credential(self, human_id: str) -> str:
        """Generate a synthetic proof for delivery through the trusted local path."""
        self.identities.require_enabled(PrincipalKind.HUMAN, human_id)
        proof, digest = self._mint()
        self._proofs[human_id] = digest
        return proof

    def authenticate(self, human_id: str, proof: str) -> str:
        self.identities.require_enabled(PrincipalKind.HUMAN, human_id)
        actual = _digest(proof, ErrorCode.INVALID_PROOF)
        expected = self._proofs.get(human_id)
        if expected is None or not compare_digest(expected, actual):
            raise AuthorityError(ErrorCode.INVALID_PROOF)

        issued_at = self.now()
        expires_at = expires_after(issued_at, SESSION_DURATION)
        session_id, _ = self._mint()
        token, digest = self._mint()
        self._sessions[session_id] = Session(session_id, human_id, issued_at, expires_at)
        self._token_sessions[digest] = session_id
        return token

    def _session_id_for_token(self, token: str) -> str:
        session_id = self._token_sessions.get(_digest(token, ErrorCode.INVALID_SESSION))
        if session_id is None:
            raise AuthorityError(ErrorCode.INVALID_SESSION)
        return session_id

    def _require_session(self, session_id: str, now: datetime) -> Session:
        session = self._sessions.get(session_id)
        if session is None or now < session.issued_at:
            raise AuthorityError(ErrorCode.INVALID_SESSION)
        if now >= session.expires_at:
            del self._sessions[session_id]
            raise AuthorityError(ErrorCode.EXPIRED_SESSION)
        self.identities.require_enabled(PrincipalKind.HUMAN, session.human_id)
        return session

    def validate_session(self, token: str) -> Session:
        return self._require_session(self._session_id_for_token(token), self.now())

    def invalidate(self, token: str) -> None:
        session_id = self._session_id_for_token(token)
        if self._sessions.pop(session_id, None) is None:
            raise AuthorityError(ErrorCode.INVALID_SESSION)

    def start_run(self, token: str, agent_id: str) -> RunBinding:
        """Assign an enabled agent to a verified session through the trusted runtime."""
        session = self.validate_session(token)
        self.identities.require_enabled(PrincipalKind.AGENT, agent_id)
        run_id, _ = self._mint()
        run = RunBinding(run_id, session.session_id, session.human_id, agent_id)
        self._runs[run_id] = run
        return run

    def validate_run(self, run: RunBinding) -> datetime:
        """Check the registered shared binding and return its validation time."""
        if (type(run) is not RunBinding or type(run.run_id) is not str
                or self._runs.get(run.run_id) is not run):
            raise AuthorityError(ErrorCode.BINDING_MISMATCH)
        now = self.now()
        session = self._require_session(run.session_id, now)
        if session.human_id != run.human_id:
            raise AuthorityError(ErrorCode.BINDING_MISMATCH)
        self.identities.require_enabled(PrincipalKind.AGENT, run.agent_id)
        return now
