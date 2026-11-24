from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import count

import pytest

from agent_authz.delegation import DelegationManager
from agent_authz.identity.principals import IdentityStore
from agent_authz.identity.sessions import RunBinding, SessionManager


@dataclass
class ManualClock:
    value: datetime = field(default_factory=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))

    def __call__(self) -> datetime:
        return self.value


@dataclass
class RuntimeFixture:
    clock: ManualClock
    identities: IdentityStore
    sessions: SessionManager
    delegations: DelegationManager

    def start(self, human_id: str = "alice", agent_id: str = "document-agent") -> tuple[str, RunBinding]:
        proof = self.sessions.provision_credential(human_id)
        token = self.sessions.authenticate(human_id, proof)
        return token, self.sessions.start_run(token, agent_id)


@pytest.fixture
def runtime():
    clock = ManualClock()
    identities = IdentityStore()
    identifiers = count(1)

    def new_id() -> str:
        return f"synthetic-test-id-{next(identifiers)}"

    sessions = SessionManager(identities, clock=clock, new_id=new_id)
    return RuntimeFixture(clock, identities, sessions, DelegationManager(sessions, new_id=new_id))
