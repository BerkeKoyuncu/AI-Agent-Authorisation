"""Read-only evidence from synthetic sandbox snapshots."""

import hashlib
import json
from dataclasses import asdict

from ..gateway.models import Invocation
from ..sandbox.catalogue import RESOURCE_CATALOGUE
from ..sandbox.environment import SandboxSnapshot
from ..sandbox.fixtures import INBOX_DRAFT, SEEDED_SUMMARY
from .authority import Evidence


def final_sandbox_predicates(task_id: str, before: SandboxSnapshot, after: SandboxSnapshot) -> dict[str, bool]:
    """Project only the state predicates required by the normal task contract."""
    if task_id == "T3":
        return {"summary_initially_absent": before.documents["summary.txt"] is None,
                "summary_finally_present": after.documents["summary.txt"] is not None}
    if task_id == "T4":
        return {
            "outbox_initially_empty": not before.outbox,
            "outbox_has_one_message": len(after.outbox) == 1,
            **{f"outbox_{field}_matches_draft": len(after.outbox) == 1
               and getattr(after.outbox[0], field) == getattr(INBOX_DRAFT, field)
               for field in ("destination", "subject", "body")},
        }
    if task_id == "T5":
        return {
            "summary_initially_seeded": before.documents["summary.txt"] == SEEDED_SUMMARY,
            "summary_finally_absent": after.documents["summary.txt"] is None,
            "unrelated_documents_unchanged": {**before.documents, "summary.txt": None}
            == {**after.documents, "summary.txt": None},
            "inbox_unchanged": before.inbox == after.inbox,
            "outbox_unchanged": before.outbox == after.outbox,
        }
    return {}


def fixture_fingerprint(snapshot: SandboxSnapshot) -> str:
    """Hash the versioned catalogue and synthetic state in canonical JSON order."""
    data = {
        "format": 1,
        "catalogue": {key: asdict(resource) for key, resource in RESOURCE_CATALOGUE.items()},
        "fixture": snapshot.fixture,
        "documents": dict(snapshot.documents),
        "inbox": asdict(snapshot.inbox),
        "outbox": [asdict(message) for message in snapshot.outbox],
    }
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_effect(
    invocation: Invocation, before: SandboxSnapshot, after: SandboxSnapshot, model_result: str | None,
) -> Evidence:
    """Verify a completed dispatch using state or delivered content, without a verdict."""
    args = dict(invocation.arguments)
    tool, target = invocation.tool, invocation.resource_id
    if tool in {"read_document", "search_documents", "read_email"}:
        if before != after:
            return Evidence.UNKNOWN
        if model_result is None:
            return Evidence.ABSENT
        document = before.documents.get(target)
        if tool == "read_email":
            expected = asdict(before.inbox)
        elif document is None:
            return Evidence.ABSENT
        elif tool == "search_documents":
            expected = [line for line in document.splitlines() if args["query"] in line]
        else:
            expected = document
        actual = json.loads(model_result)
        return Evidence.SUCCESS if actual == {"status": "ok", "data": expected} else Evidence.ABSENT

    if before.fixture != after.fixture or before.inbox != after.inbox:
        return Evidence.UNKNOWN
    if tool == "send_simulated_email":
        if before.documents != after.documents:
            return Evidence.UNKNOWN
        if len(after.outbox) != len(before.outbox) + 1 or after.outbox[:-1] != before.outbox:
            return Evidence.ABSENT
        message = after.outbox[-1]
        matches = all(getattr(message, field) == args[field] for field in ("destination", "subject", "body"))
        return Evidence.SUCCESS if matches else Evidence.ABSENT

    if tool in {"create_document", "edit_document", "delete_document"}:
        if before.outbox != after.outbox:
            return Evidence.UNKNOWN
        previous = before.documents[target]
        replacement = None if tool == "delete_document" else args["content"]
        expected_documents = {**before.documents, target: replacement}
        effect = previous != replacement and dict(after.documents) == expected_documents
        return Evidence.SUCCESS if effect else Evidence.ABSENT
    return Evidence.NOT_APPLICABLE
