"""Correlate independent gateway attempts with ordered, validated journal records."""

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from enum import StrEnum

from ..gateway.models import Decision, Execution, PolicyMode, Reason
from .observations import AttemptObservation, OutcomeObservation
from .reader import Journal, JournalRecord
from .schema import (
    BINDING_FIELDS, EVENT_ORDER, LIFECYCLE_EXECUTION, OPERATION_FIELDS, TASK_FIELDS, VERSION_FIELDS, is_duration,
)


class Status(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    INCONSISTENT = "inconsistent"
    UNKNOWN = "unknown"


class Issue(StrEnum):
    MISSING_CORRELATION = "missing_correlation"
    MISSING_EVENT = "missing_event"
    UNCONFIRMED_WRITE = "unconfirmed_write"
    MISSING_TERMINAL_OBSERVATION = "missing_terminal_observation"
    MISSING_PRELIMINARY_OBSERVATION = "missing_preliminary_observation"
    MISSING_VALIDATION_OBSERVATION = "missing_validation_observation"
    MISSING_BINDING_OBSERVATION = "missing_binding_observation"
    MISSING_OPERATION_OBSERVATION = "missing_operation_observation"
    DUPLICATE_ATTEMPT = "duplicate_attempt"
    SHARED_REQUEST_ID = "shared_request_id"
    DUPLICATE_EVENT = "duplicate_event"
    UNEXPECTED_EVENT = "unexpected_event"
    EVENT_ORDER = "event_order"
    POLICY_CONFLICT = "policy_conflict"
    BINDING_CONFLICT = "binding_conflict"
    OPERATION_CONFLICT = "operation_conflict"
    VALIDATION_CONFLICT = "validation_conflict"
    DECISION_CONFLICT = "decision_conflict"
    VERSION_CONFLICT = "version_conflict"
    DISPATCH_CONFLICT = "dispatch_conflict"
    EXECUTION_CONFLICT = "execution_conflict"
    EFFECT_CONFLICT = "effect_conflict"
    LIFECYCLE_CONFLICT = "lifecycle_conflict"
    TIMING_CONFLICT = "timing_conflict"
    ORPHAN_EVENT = "orphan_event"
    UNCORRELATED_EVENT = "uncorrelated_event"


_INCOMPLETE = {Issue.MISSING_CORRELATION, Issue.MISSING_EVENT, Issue.UNCONFIRMED_WRITE}
_UNKNOWN = {Issue.MISSING_TERMINAL_OBSERVATION, Issue.MISSING_PRELIMINARY_OBSERVATION, Issue.MISSING_VALIDATION_OBSERVATION,
            Issue.MISSING_BINDING_OBSERVATION, Issue.MISSING_OPERATION_OBSERVATION}
_STAGE_INDEX = {event: index for index, event in enumerate(EVENT_ORDER)}


@dataclass(frozen=True, slots=True)
class Problem:
    issue: Issue
    event: str | None = None
    line: int | None = None


@dataclass(frozen=True, slots=True)
class AttemptAssessment:
    observation: AttemptObservation
    status: Status
    records: tuple[JournalRecord, ...]
    required_events: tuple[str, ...]
    problems: tuple[Problem, ...]


@dataclass(frozen=True, slots=True)
class AuditAssessment:
    journal: Journal
    attempts: tuple[AttemptAssessment, ...]
    orphan_lines: tuple[int, ...]
    uncorrelated_lines: tuple[int, ...]

    @property
    def denominator(self) -> int:
        return len(self.attempts)

    @property
    def counts(self) -> dict[Status, int]:
        observed = Counter(attempt.status for attempt in self.attempts)
        return {status: observed[status] for status in Status}

    @property
    def numerator(self) -> int:
        return self.counts[Status.COMPLETE]

    @property
    def fraction(self) -> float | None:
        return self.numerator / self.denominator if self.denominator else None

    @property
    def invalid_records(self) -> int:
        return self.journal.invalid_records

    @property
    def issue_counts(self) -> dict[str, int]:
        counts = Counter(problem.issue.value for attempt in self.attempts for problem in attempt.problems)
        counts.update(problem.issue.value for problem in self.journal.problems)
        counts.update(Issue.ORPHAN_EVENT.value for _ in self.orphan_lines)
        counts.update(Issue.UNCORRELATED_EVENT.value for _ in self.uncorrelated_lines)
        return dict(counts)

    @property
    def globally_clean(self) -> bool:
        return (self.numerator == self.denominator and not self.journal.problems
                and not self.orphan_lines and not self.uncorrelated_lines)


def _status(problems: list[Problem]) -> Status:
    codes = {problem.issue for problem in problems}
    if codes - _INCOMPLETE - _UNKNOWN:
        return Status.INCONSISTENT
    if codes & _INCOMPLETE:
        return Status.INCOMPLETE
    return Status.UNKNOWN if codes else Status.COMPLETE


def _path(observed: AttemptObservation, outcome: OutcomeObservation) -> tuple[str, ...]:
    failed = outcome.failed_writes
    # Required writes stop at the first pre-dispatch failure, then the gateway
    # tries to record admission denial. Re-entrant rejection has no callback.
    written = tuple(name for name, _ in outcome.timing.audit_writes_ns)
    if not written and outcome.decision.reason is Reason.RUNTIME_UNAVAILABLE and failed == ("attempt",):
        return ()
    for index, event in enumerate(EVENT_ORDER[:4]):
        if event in failed:
            return (*EVENT_ORDER[:index + 1], "admission")
    if outcome.dispatched:
        return (*EVENT_ORDER[:7], "lifecycle") if outcome.lifecycle is not None else EVENT_ORDER[:7]
    if observed.structural_valid is False or (observed.structural_valid is None and "preliminary" not in written):
        return ("attempt", "validation", "admission")
    if "dispatch_intent" in written:
        return (*EVENT_ORDER[:4], "admission")
    return (*EVENT_ORDER[:3], "admission")


def _record_problem(problems: list[Problem], code: Issue, row: JournalRecord) -> None:
    problems.append(Problem(code, row.event, row.line))


def _check_metadata(
    observed: AttemptObservation, records: tuple[JournalRecord, ...], problems: list[Problem],
) -> None:
    if not records:
        return
    first = records[0].fields
    binding = asdict(observed.binding) if observed.binding is not None else None
    operation = asdict(observed.operation) if observed.operation is not None else None
    scoped: tuple[object, ...] | None = None
    scope_observed = False
    for row in records:
        fields = row.fields
        if (fields["policy_mode"] != observed.mode or fields["policy_version"] != first["policy_version"]
                or (observed.outcome is not None
                    and fields["policy_version"] != observed.outcome.decision.policy_version)):
            _record_problem(problems, Issue.POLICY_CONFLICT, row)
        if (any(fields.get(key) != first.get(key) for key in BINDING_FIELDS)
                or (binding is not None and any(fields.get(key) != binding[key] for key in BINDING_FIELDS))
                or (observed.run_id is not None and fields.get("run_id") not in (None, observed.run_id))):
            _record_problem(problems, Issue.BINDING_CONFLICT, row)
        scope = tuple(fields.get(key) for key in TASK_FIELDS)
        if scope != (None, None):
            scope_observed = True
            if scoped is None:
                scoped = scope
            if scoped != scope or (binding is not None and scope != tuple(binding[key] for key in TASK_FIELDS)):
                _record_problem(problems, Issue.BINDING_CONFLICT, row)
        elif scoped is not None or (observed.mode is PolicyMode.C and row.event == "admission"
                                    and observed.outcome is not None
                                    and observed.outcome.decision.versions.delegation is not None):
            _record_problem(problems, Issue.BINDING_CONFLICT, row)
        keys = (*OPERATION_FIELDS, "destination")
        if (any(fields.get(key) != first.get(key) for key in keys)
                or (operation is not None and any(fields.get(key) != operation[key] for key in keys))
                or (observed.structural_valid is False and "tool" in fields)):
            _record_problem(problems, Issue.OPERATION_CONFLICT, row)
    if binding is None and ("run_id" in first or scope_observed):
        problems.append(Problem(Issue.MISSING_BINDING_OBSERVATION))


def _check_versions(
    observed: AttemptObservation, records: tuple[JournalRecord, ...], problems: list[Problem],
) -> None:
    previous = [None, None, None]
    before = observed.before_versions
    after = observed.after_versions
    lower = (before.human, before.agent, before.delegation) if before else (None, None, None)
    upper = (after.human, after.agent, after.delegation) if after else (None, None, None)
    for row in records:
        if row.event not in {"preliminary", "dispatch_intent", "admission"}:
            continue
        for index, field in enumerate(VERSION_FIELDS):
            value = row.fields[field]
            if value is None:
                continue
            if ((previous[index] is not None and value < previous[index])
                    or (lower[index] is not None and value < lower[index])
                    or (upper[index] is not None and value > upper[index])):
                _record_problem(problems, Issue.VERSION_CONFLICT, row)
            previous[index] = value


def _check_timings(
    records: tuple[JournalRecord, ...], outcome: OutcomeObservation | None, problems: list[Problem],
) -> None:
    timing = outcome.timing if outcome else None
    writes: dict[str, tuple[tuple[str, int], ...]] = {}
    if timing:
        policy, enforcement, executor = timing.policy_ns, timing.enforcement_ns, timing.executor_ns
        if (not is_duration(enforcement) or not is_duration(timing.gateway_overhead_ns)
                or timing.gateway_overhead_ns < enforcement
                or (timing.audit_writes_ns and policy is None)
                or (policy is not None and (not is_duration(policy) or policy > enforcement))
                or (outcome.dispatched and not is_duration(executor))
                or (not outcome.dispatched and executor is not None)):
            problems.append(Problem(Issue.TIMING_CONFLICT))
        for index, (event, duration) in enumerate(timing.audit_writes_ns):
            if event in writes or event not in _STAGE_INDEX or not is_duration(duration):
                problems.append(Problem(Issue.TIMING_CONFLICT))
                continue
            writes[event] = timing.audit_writes_ns[:index]
    prior: tuple[tuple[str, int], ...] = ()
    for row in records:
        current = row.fields["prior_audit_writes_ns"]
        stages = [_STAGE_INDEX[name] for name, _ in current]
        conflict = (list(sorted(set(stages))) != stages or any(stage >= _STAGE_INDEX[row.event] for stage in stages)
                    or current[:len(prior)] != prior)
        if timing:
            terminal = _STAGE_INDEX[row.event] >= _STAGE_INDEX["admission"]
            expected = (timing.policy_ns, timing.enforcement_ns if terminal else None,
                        timing.executor_ns if terminal else None)
            actual = tuple(row.fields[key] for key in ("policy_ns", "enforcement_ns", "executor_ns"))
            conflict |= actual != expected or (row.event in writes and current != writes[row.event])
        if conflict:
            _record_problem(problems, Issue.TIMING_CONFLICT, row)
        prior = current


def _check_path(
    observed: AttemptObservation, records: tuple[JournalRecord, ...], problems: list[Problem],
) -> tuple[str, ...]:
    names = tuple(record.event for record in records)
    counts = Counter(names)
    for event, count in counts.items():
        if count > 1:
            problems.append(Problem(Issue.DUPLICATE_EVENT, event))
    if sorted(names, key=_STAGE_INDEX.__getitem__) != list(names):
        problems.append(Problem(Issue.EVENT_ORDER))
    outcome = observed.outcome
    required = _path(observed, outcome) if outcome is not None else ()
    if outcome is None:
        problems.append(Problem(Issue.MISSING_TERMINAL_OBSERVATION))
    else:
        writes = tuple(event for event, _ in outcome.timing.audit_writes_ns)
        if writes != required:
            problems.append(Problem(Issue.TIMING_CONFLICT))
        if outcome.dispatched != (outcome.execution is not Execution.NOT_DISPATCHED):
            problems.append(Problem(Issue.DISPATCH_CONFLICT))
        if outcome.dispatched and any(event in EVENT_ORDER[:4] for event in outcome.failed_writes):
            problems.append(Problem(Issue.DISPATCH_CONFLICT))
        if outcome.decision.allowed != outcome.dispatched:
            problems.append(Problem(Issue.DECISION_CONFLICT))
        if outcome.dispatched and observed.structural_valid is False:
            problems.append(Problem(Issue.VALIDATION_CONFLICT))
        if observed.effect == "observed_success" and (not outcome.dispatched or outcome.execution is Execution.FAILED):
            problems.append(Problem(Issue.EFFECT_CONFLICT))
        if outcome.decision.mode != observed.mode:
            problems.append(Problem(Issue.POLICY_CONFLICT))
        for name in outcome.failed_writes:
            problems.append(Problem(Issue.UNCONFIRMED_WRITE, name if name in _STAGE_INDEX else None))
        for name in required:
            if not counts[name]:
                problems.append(Problem(Issue.MISSING_EVENT, name))
        for row in records:
            if row.event not in required:
                _record_problem(problems, Issue.UNEXPECTED_EVENT, row)
    if observed.structural_valid is None:
        problems.append(Problem(Issue.MISSING_VALIDATION_OBSERVATION))
    if observed.structural_valid is True and observed.operation is None:
        problems.append(Problem(Issue.MISSING_OPERATION_OBSERVATION))
    return required


def _compare_decision(row: JournalRecord, decision: Decision, problems: list[Problem]) -> None:
    fields = row.fields
    if (fields["allowed"], fields["reason"]) != (decision.allowed, decision.reason):
        _record_problem(problems, Issue.DECISION_CONFLICT, row)
    versions = tuple(fields[field] for field in VERSION_FIELDS)
    if versions != (decision.versions.human, decision.versions.agent, decision.versions.delegation):
        _record_problem(problems, Issue.VERSION_CONFLICT, row)


def _check_decisions(
    observed: AttemptObservation, records: tuple[JournalRecord, ...], problems: list[Problem],
) -> None:
    # Keep the full sequence for duplicate detection and for checking every
    # conflicting row. These lookups only collect sets of reported values.
    outcome = observed.outcome
    preliminary = outcome.preliminary if outcome is not None else None
    if preliminary is None:
        problems.append(Problem(Issue.MISSING_PRELIMINARY_OBSERVATION))
    stages: dict[str, list[JournalRecord]] = defaultdict(list)
    for row in records:
        stages[row.event].append(row)
    prior_denial = any(row.fields["allowed"] is False for row in stages["preliminary"])
    final_denial = any(row.fields["allowed"] is False for row in stages["admission"])
    for row in records:
        fields = row.fields
        if row.event == "validation":
            if observed.structural_valid is not None and fields["valid"] != observed.structural_valid:
                _record_problem(problems, Issue.VALIDATION_CONFLICT, row)
            elif (fields["valid"] is False and outcome and outcome.decision.reason is not Reason.AUDIT_UNAVAILABLE
                  and fields["reason"] != outcome.decision.reason):
                _record_problem(problems, Issue.VALIDATION_CONFLICT, row)
        elif row.event == "preliminary" and preliminary is not None:
            if preliminary.decision is None:
                _record_problem(problems, Issue.DECISION_CONFLICT, row)
            else:
                _compare_decision(row, preliminary.decision, problems)
        elif row.event == "dispatch_intent" and prior_denial:
            _record_problem(problems, Issue.DECISION_CONFLICT, row)
        elif row.event == "admission":
            if fields["allowed"] and prior_denial:
                _record_problem(problems, Issue.DECISION_CONFLICT, row)
            if outcome:
                _compare_decision(row, outcome.decision, problems)
        elif row.event in {"dispatch", "outcome", "lifecycle"}:
            if final_denial or (outcome is not None and not outcome.dispatched):
                _record_problem(problems, Issue.DISPATCH_CONFLICT, row)
            if row.event == "outcome" and outcome:
                if (fields["execution"], fields["reason"]) != (outcome.execution, outcome.execution_reason):
                    _record_problem(problems, Issue.EXECUTION_CONFLICT, row)
            if row.event == "lifecycle":
                expected_execution = LIFECYCLE_EXECUTION[fields["status"]]
                if ((outcome and fields["status"] != outcome.lifecycle)
                        or any(item.fields["execution"] != expected_execution for item in stages["outcome"])):
                    _record_problem(problems, Issue.LIFECYCLE_CONFLICT, row)


def assess_journal(journal: Journal, observations: Iterable[AttemptObservation]) -> AuditAssessment:
    """Assess supplied gateway entries once each, preserving journal multiplicity."""
    attempts: dict[tuple[str | None, int], AttemptObservation] = {}
    duplicate_keys = set()
    for observation in observations:
        key = (observation.run_id, observation.sequence)
        if key in attempts:
            duplicate_keys.add(key)
        else:
            attempts[key] = observation
    known = Counter(obs.request_id for obs in attempts.values() if obs.request_id is not None)
    grouped: dict[str, list[JournalRecord]] = defaultdict(list)
    orphans, uncorrelated = [], []
    for row in journal.records:
        count = known[row.request_id]
        if count == 1:
            grouped[row.request_id].append(row)
        elif count == 0:
            orphans.append(row.line)
        else:
            uncorrelated.append(row.line)

    assessments = []
    for key, observation in attempts.items():
        problems: list[Problem] = []
        if key in duplicate_keys:
            problems.append(Problem(Issue.DUPLICATE_ATTEMPT))
        request_id = observation.request_id
        if request_id is None:
            problems.append(Problem(Issue.MISSING_CORRELATION))
        elif known[request_id] > 1:
            problems.append(Problem(Issue.SHARED_REQUEST_ID))
        records = tuple(grouped.get(request_id, ()))
        required = _check_path(observation, records, problems)
        _check_metadata(observation, records, problems)
        _check_versions(observation, records, problems)
        _check_timings(records, observation.outcome, problems)
        _check_decisions(observation, records, problems)
        assessments.append(AttemptAssessment(observation, _status(problems), records, required, tuple(problems)))
    return AuditAssessment(journal, tuple(assessments), tuple(orphans), tuple(uncorrelated))
