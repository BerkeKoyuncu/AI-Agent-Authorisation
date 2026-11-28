"""Structural validation and pure policy analysis of the fixed permission universe."""

import json
from dataclasses import dataclass

from ..agent.runtime import prepare_task
from ..gateway import PolicyMode
from ..gateway.policies import evaluate
from ..gateway.registry import TOOL_REGISTRY, ValidationError, canonicalise
from ..sandbox.catalogue import RESOURCE_CATALOGUE
from ..sandbox.fixtures import AGENDA_QUERY, INBOX_DRAFT
from ..scenarios.authority import Authority, Lifecycle, label_attempt
from ..scenarios.catalogue import CASES, PERMISSION_INVENTORY
from ..scenarios.evidence import fixture_fingerprint


def permission_candidates() -> tuple[str, ...]:
    """Stable JSON descriptions of candidate requests for schema and PDP use only."""
    candidates = []
    for slot in PERMISSION_INVENTORY:
        resource = RESOURCE_CATALOGUE[slot.resource_id]
        tool, = (name for name, spec in TOOL_REGISTRY.items()
                 if spec.kind is resource.kind and spec.action == slot.action)
        arguments = {"resource_id": slot.resource_id}
        if slot.action == "search":
            arguments["query"] = AGENDA_QUERY if slot.resource_id == "meeting_notes.txt" else "synthetic"
        elif slot.action in {"create", "edit"}:
            arguments["content"] = "Synthetic schema validation text."
        elif slot.action == "send":
            arguments.update(destination=slot.destination, subject=INBOX_DRAFT.subject, body=INBOX_DRAFT.body)
        candidates.append(json.dumps({"tool": tool, "arguments": arguments}, sort_keys=True, separators=(",", ":")))
    return tuple(candidates)


@dataclass(frozen=True, slots=True)
class CandidateAssessment:
    case: str
    policy: PolicyMode
    fixture: str
    candidate: int
    authority: Authority
    admitted: bool | None
    reason: str


def analyse_permissions(candidates: tuple[str, ...]) -> tuple[CandidateAssessment, ...]:
    assessments = []
    for case in (case for case in CASES.values() if case.methods):
        for mode in PolicyMode:
            prepared = prepare_task(case.task_id, mode, lambda _: None)
            state = prepared.observe_authority()
            before = prepared.sandbox.snapshot()
            fingerprint = fixture_fingerprint(before)
            for number, raw in enumerate(candidates, 1):
                try:
                    invocation = canonicalise(json.loads(raw))
                except (ValidationError, ValueError):
                    assessments.append(CandidateAssessment(case.case_id, mode, fingerprint, number, Authority.UNKNOWN,
                                                           None, "invalid_candidate"))
                    continue
                label = label_attempt(case.task_id, invocation, structural_valid=True, binding_valid=state.shared_valid,
                                      lifecycle=Lifecycle.ACTIVE)
                if state.shared_valid and state.delegation is not None:
                    decision = evaluate(mode, invocation, state.human, state.agent,
                                        state.delegation if mode is PolicyMode.C else None)
                    admitted, reason = decision.allowed, decision.reason
                else:
                    admitted, reason = None, "missing_initial_authority"
                assessments.append(CandidateAssessment(case.case_id, mode, fingerprint, number, label.authority,
                                                       admitted, reason))
            if prepared.sandbox.snapshot() != before or prepared.observe_authority() != state:
                raise RuntimeError("Permission analysis changed the initial snapshot.")
    return tuple(assessments)


def permission_summary(assessments: tuple[CandidateAssessment, ...]) -> list[dict[str, object]]:
    groups: dict[tuple[str, PolicyMode], list[CandidateAssessment]] = {}
    for row in assessments:
        groups.setdefault((row.case, row.policy), []).append(row)
    summary = []
    for (case, mode), rows in groups.items():
        missing = sum(row.admitted is None or row.authority is Authority.UNKNOWN for row in rows)
        excess = sum(row.admitted is True and row.authority is Authority.UNAUTHORISED for row in rows)
        summary.append({"case": case, "policy": mode, "universe": len(rows),
                        "admitted": sum(row.admitted is True for row in rows),
                        "task_authorised": sum(row.authority is Authority.AUTHORISED for row in rows),
                        "admitted_unauthorised": excess, "missing": missing,
                        "excessive_privilege": excess / len(rows) if rows and not missing else None})
    return summary
