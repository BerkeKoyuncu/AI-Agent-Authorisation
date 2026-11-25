"""Pure policy decisions over canonical calls and trusted record snapshots."""

from types import MappingProxyType

from ..delegation import DelegationRecord
from ..identity.principals import Principal
from ..models import Action, Permission
from ..sandbox.catalogue import RESOURCE_CATALOGUE
from ..sandbox.environment import SIMULATOR_DESTINATIONS
from .models import Decision, Invocation, PolicyMode, Reason, RecordVersions
from .registry import TOOL_REGISTRY


_STATIC_GRANTS = frozenset(
    Permission(spec.action, resource.resource_id)
    for spec in TOOL_REGISTRY.values()
    for resource in RESOURCE_CATALOGUE.values()
    if spec.kind is resource.kind
)
_ALLOWLISTS = MappingProxyType({
    "document-agent": frozenset({"read_document", "search_documents", "create_document", "delete_document"}),
    "email-agent": frozenset({"read_email", "send_simulated_email"}),
})


def _scoped_reason(
    invocation: Invocation, human: Principal, agent: Principal, delegation: DelegationRecord,
) -> Reason:
    permission = Permission(invocation.action, invocation.resource_id)
    destination = dict(invocation.arguments).get("destination")
    for grants, denial in (
        (human.grants, Reason.HUMAN_GRANT_DENIED),
        (agent.grants, Reason.AGENT_GRANT_DENIED),
        (delegation.grants, Reason.OUTSIDE_TASK_SCOPE),
    ):
        grant = next((item for item in grants if item.permission == permission), None)
        if grant is None:
            return denial
        if invocation.action is Action.SEND and (not grant.destinations or destination not in grant.destinations):
            return Reason.DESTINATION_DENIED
        if invocation.action is Action.SEARCH:
            required = Permission(Action.READ, invocation.resource_id)
            if not any(item.permission == required for item in grants):
                return Reason.READ_REQUIRED
    return Reason.ALLOWED


def evaluate(
    mode: PolicyMode, invocation: Invocation, human: Principal, agent: Principal,
    delegation: DelegationRecord | None = None,
) -> Decision:
    """Evaluate the selected fixed profile. The gateway supplies validated records."""
    versions = RecordVersions(human.version, agent.version, delegation.version if delegation else None)
    if mode is PolicyMode.A:
        permission = Permission(invocation.action, invocation.resource_id)
        allowed = permission in _STATIC_GRANTS
        if invocation.action is Action.SEND:
            allowed = allowed and dict(invocation.arguments).get("destination") in SIMULATOR_DESTINATIONS
        reason = Reason.ALLOWED if allowed else Reason.STATIC_GRANT_DENIED
    elif mode is PolicyMode.B:
        allowlist = _ALLOWLISTS.get(agent.principal_id)
        allowed = allowlist is not None and invocation.tool in allowlist
        reason = Reason.ALLOWED if allowed else Reason.TOOL_NOT_ALLOWLISTED
    elif mode is PolicyMode.C and delegation is not None:
        reason = _scoped_reason(invocation, human, agent, delegation)
    else:
        reason = Reason.INVALID_CONTEXT
    return Decision(mode, reason, versions)
