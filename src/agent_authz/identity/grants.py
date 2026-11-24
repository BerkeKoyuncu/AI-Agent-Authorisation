"""Validated exact permissions and immutable simulator route constraints."""

from dataclasses import dataclass

from ..models import Action, Permission
from ..sandbox.catalogue import RESOURCE_CATALOGUE, ResourceKind
from ..sandbox.environment import SIMULATOR_DESTINATIONS
from .errors import AuthorityError, ErrorCode


_ACTIONS_BY_KIND = {
    ResourceKind.DOCUMENT: frozenset({Action.READ, Action.SEARCH, Action.CREATE, Action.EDIT, Action.DELETE}),
    ResourceKind.INBOX: frozenset({Action.READ}),
    ResourceKind.OUTBOX: frozenset({Action.SEND}),
}


@dataclass(frozen=True, slots=True)
class Grant:
    permission: Permission
    destinations: frozenset[str] | None = None

    def __post_init__(self) -> None:
        if (type(self.permission) is not Permission or type(self.permission.action) is not Action
                or type(self.permission.resource_id) is not str):
            raise AuthorityError(ErrorCode.INVALID_GRANT)
        resource = RESOURCE_CATALOGUE.get(self.permission.resource_id)
        if resource is None or self.permission.action not in _ACTIONS_BY_KIND[resource.kind]:
            raise AuthorityError(ErrorCode.INVALID_GRANT)

        if self.permission.action is Action.SEND:
            if (type(self.destinations) is not frozenset or not self.destinations
                    or any(type(route) is not str for route in self.destinations)
                    or not self.destinations <= SIMULATOR_DESTINATIONS):
                raise AuthorityError(ErrorCode.INVALID_CONSTRAINT)
        elif self.destinations is not None:
            raise AuthorityError(ErrorCode.INVALID_CONSTRAINT)


def validate_grants(grants: frozenset[Grant]) -> None:
    """Require immutable grants and one constraint set per exact pair."""
    if type(grants) is not frozenset or any(type(grant) is not Grant for grant in grants):
        raise AuthorityError(ErrorCode.INVALID_GRANT)
    if len({grant.permission for grant in grants}) != len(grants):
        raise AuthorityError(ErrorCode.INVALID_CONSTRAINT)


def covers_grants(available: frozenset[Grant], requested: frozenset[Grant]) -> bool:
    """Check exact pairs and, for sends, inclusion in the available route set."""
    by_permission = {grant.permission: grant.destinations for grant in available}
    for grant in requested:
        if grant.permission not in by_permission:
            return False
        routes = by_permission[grant.permission]
        if grant.destinations is not None and (routes is None or not grant.destinations <= routes):
            return False
    return True
