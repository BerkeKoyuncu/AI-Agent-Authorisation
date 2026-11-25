"""Shared strict schemas and explicit sandbox handler bindings."""

from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeGuard

from ..models import Action
from ..sandbox.catalogue import RESOURCE_CATALOGUE, ResourceKind
from ..sandbox.environment import (
    MAX_BODY_LENGTH, MAX_DOCUMENT_LENGTH, MAX_QUERY_LENGTH, MAX_SUBJECT_LENGTH,
    SIMULATOR_DESTINATIONS, SandboxEnvironment,
)
from .models import Invocation, Reason, ToolData


@dataclass(frozen=True, slots=True)
class Argument:
    name: str
    minimum: int = 0
    maximum: int | None = None


@dataclass(frozen=True, slots=True)
class ToolSpec:
    action: Action
    kind: ResourceKind
    description: str
    handler: Callable[..., ToolData]
    extra: tuple[Argument, ...] = ()

    @property
    def arguments(self) -> tuple[Argument, ...]:
        return (Argument("resource_id"), *self.extra)


TOOL_REGISTRY = MappingProxyType({
    "read_document": ToolSpec(Action.READ, ResourceKind.DOCUMENT, "Read a synthetic document.",
                              SandboxEnvironment.read_document),
    "search_documents": ToolSpec(Action.SEARCH, ResourceKind.DOCUMENT, "Search one synthetic document literally.",
                                 SandboxEnvironment.search_documents, (Argument("query", 1, MAX_QUERY_LENGTH),)),
    "create_document": ToolSpec(Action.CREATE, ResourceKind.DOCUMENT, "Create content in an absent document slot.",
                                SandboxEnvironment.create_document, (Argument("content", maximum=MAX_DOCUMENT_LENGTH),)),
    "edit_document": ToolSpec(Action.EDIT, ResourceKind.DOCUMENT, "Replace the content of an existing document.",
                              SandboxEnvironment.edit_document, (Argument("content", maximum=MAX_DOCUMENT_LENGTH),)),
    "delete_document": ToolSpec(Action.DELETE, ResourceKind.DOCUMENT, "Clear an existing document slot.",
                                SandboxEnvironment.delete_document),
    "read_email": ToolSpec(Action.READ, ResourceKind.INBOX, "Read the simulated inbox draft.",
                           SandboxEnvironment.read_email),
    "send_simulated_email": ToolSpec(
        Action.SEND, ResourceKind.OUTBOX, "Append a message to the simulated outbox.",
        SandboxEnvironment.send_simulated_email,
        (Argument("destination"), Argument("subject", maximum=MAX_SUBJECT_LENGTH),
         Argument("body", maximum=MAX_BODY_LENGTH)),
    ),
})


def tool_schemas() -> list[dict[str, object]]:
    """Return detached, provider-independent tool schema descriptions."""
    schemas = []
    for name, spec in TOOL_REGISTRY.items():
        properties: dict[str, dict[str, object]] = {}
        for field in spec.arguments:
            schema: dict[str, object] = {"type": "string"}
            if field.name == "resource_id":
                schema["description"] = f"Exact registered {spec.kind} identifier."
            elif field.name == "destination":
                schema["enum"] = sorted(SIMULATOR_DESTINATIONS)
            else:
                schema.update(minLength=field.minimum, maxLength=field.maximum)
            properties[field.name] = schema
        schemas.append({
            "name": name,
            "description": spec.description,
            "parameters": {"type": "object", "properties": properties,
                           "required": list(properties), "additionalProperties": False},
        })
    return schemas


class ValidationError(Exception):
    def __init__(self, reason: Reason) -> None:
        super().__init__(reason.value)
        self.reason = reason


def _has_fields(value: object, fields: set[str]) -> TypeGuard[dict[str, object]]:
    return (type(value) is dict and len(value) == len(fields)
            and all(type(key) is str for key in value) and value.keys() == fields)


def canonicalise(request: object) -> Invocation:
    """Accept only the decoded envelope and exact schema in the trusted registry."""
    if not _has_fields(request, {"tool", "arguments"}):
        raise ValidationError(Reason.INVALID_ENVELOPE)
    tool = request["tool"]
    if type(tool) is not str:
        raise ValidationError(Reason.INVALID_ENVELOPE)
    spec = TOOL_REGISTRY.get(tool)
    if spec is None:
        raise ValidationError(Reason.UNKNOWN_TOOL)
    raw = request["arguments"]
    fields = spec.arguments
    if not _has_fields(raw, {field.name for field in fields}):
        raise ValidationError(Reason.INVALID_ARGUMENT)
    arguments: dict[str, str] = {}
    for field in fields:
        value = raw[field.name]
        if type(value) is not str or (field.maximum is not None and not field.minimum <= len(value) <= field.maximum):
            raise ValidationError(Reason.INVALID_ARGUMENT)
        arguments[field.name] = value

    resource_id = arguments["resource_id"]
    resource = RESOURCE_CATALOGUE.get(resource_id)
    if resource is None or resource.kind is not spec.kind:
        raise ValidationError(Reason.UNSUPPORTED_RESOURCE)
    if spec.action is Action.SEND and arguments["destination"] not in SIMULATOR_DESTINATIONS:
        raise ValidationError(Reason.UNREGISTERED_DESTINATION)
    return Invocation(tool, spec.action, resource.resource_id, tuple(arguments.items()))
