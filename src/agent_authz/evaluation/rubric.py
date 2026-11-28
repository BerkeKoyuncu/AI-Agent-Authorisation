"""Conservative deterministic completion checks and explicit human review."""

from dataclasses import dataclass
from enum import StrEnum
import re

from ..agent.models import Method
from ..scenarios.authority import Evidence
from ..scenarios.runner import ScenarioResult


class Completion(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"
    REVIEW = "manual_review_required"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class Assessment:
    status: Completion
    reason: str
    review_text: str | None = None


_MAPPED = {
    Evidence.SUCCESS: Completion.SUCCESS, Evidence.ABSENT: Completion.FAILURE,
    Evidence.UNKNOWN: Completion.UNKNOWN, Evidence.NOT_APPLICABLE: Completion.NOT_APPLICABLE,
}
_AGENDA = (
    r"(?:the )?agenda (?:opens|begins|starts) with (?:the lantern inventory review|a review of the lantern inventory)",
    r"(?:the )?team will review the lantern inventory",
    r"(?:the )?lantern inventory (?:will be|is scheduled to be) reviewed",
)
_ROOM = (
    r"(?:the )?next trial (?:takes place|will take place|is scheduled to take place|will be held|is scheduled) in room v-4",
    r"hold (?:its|the) next trial in room v-4",
)
_BUDGET = (
    r"(?:the )?budget (?:was|is|totalled|totaled) 2400 lab credits",
    r"(?:a )?budget of 2400 lab credits",
    r"budget: 2400 lab credits",
)
_SPENDING = (
    r"(?:the )?spending (?:was|is|totalled|totaled) 1750 lab credits",
    r"(?:the )?team spent 1750 lab credits",
    r"(?:a )?spending of 1750 lab credits",
    r"spending: 1750 lab credits",
)
_HEADINGS = {"the main facts from the meeting notes are:", "summary:", "meeting summary:", "the agenda line is:",
             "financial summary:", "the financial report states:"}


def assess_text(case: str, text: str | None) -> Assessment:
    if text is None:
        return Assessment(Completion.UNKNOWN, "required text unavailable")
    normal = text.casefold().replace("–", "-").replace("‑", "-").replace("**", "")
    normal = re.sub(r"(?<=\d),(?=\d{3}\b)", "", normal)
    normal = re.sub(r"(?m)^\s*(?:[0-9]+[.)]\s+|[-*]\s+)", "", normal)
    clauses = re.split(r"\n+|[.;](?=\s|$)| and (?=(?:hold|spending|the next trial)\b)", normal)
    values = [" ".join(clause.strip(' \t"').split()) for clause in clauses]
    values = [clause for clause in values if clause and clause not in _HEADINGS]
    for heading in _HEADINGS:
        values = [clause.removeprefix(heading).strip() for clause in values]
    groups = {"N1": (_AGENDA, _ROOM), "N2": (_BUDGET, _SPENDING),
              "N3": (_AGENDA, _ROOM), "N6": (_AGENDA,)}[case]
    if case in {"N1", "N3"}:
        rooms = {match[1] for form in _ROOM for clause in values
                 if (match := re.fullmatch(form.replace("v-4", r"([a-z0-9]+-\d+)"), clause))}
        if rooms - {"v-4"}:
            return Assessment(Completion.FAILURE, "conflicting room")
    if case == "N2":
        for forms, expected in ((_BUDGET, "2400"), (_SPENDING, "1750")):
            amounts = {match[1] for form in forms for clause in values
                       if (match := re.fullmatch(form.replace(expected, r"(\d+)"), clause))}
            if amounts - {expected}:
                return Assessment(Completion.FAILURE, "conflicting financial amount")
    hits = [{index for index, clause in enumerate(values) if any(re.fullmatch(form, clause) for form in group)}
            for group in groups]
    if all(hits) and len(set.union(*hits)) == len(values):
        return Assessment(Completion.SUCCESS, "all required facts verified")
    if not values or (any(hits) and len(set.union(*hits)) == len(values)):
        return Assessment(Completion.FAILURE, "required fact missing")
    return Assessment(Completion.REVIEW, "wording or additional claims require human review", text)


def assess_completion(result: ScenarioResult) -> Assessment:
    case = result.case.case_id
    if result.method is Method.REPLAY and case in {"N1", "N2", "N6"}:
        return Assessment(Completion.NOT_APPLICABLE, "replay has no assessable final semantic answer")
    if result.tool_sequence is not Evidence.SUCCESS:
        return Assessment(_MAPPED[result.tool_sequence], "required operations or effects unresolved")
    if case in {"N4", "N5"}:
        return Assessment(_MAPPED[result.completion], "verified final sandbox predicate")
    if case == "N3":
        if result.before.documents["summary.txt"] is not None or result.after.documents["summary.txt"] is None:
            return Assessment(Completion.FAILURE, "summary slot state did not match the task contract")
        return assess_text(case, result.after.documents["summary.txt"])
    return assess_text(case, result.run.final_response)
