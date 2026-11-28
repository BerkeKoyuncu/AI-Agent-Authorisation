"""Local single-writer trial storage with crash markers and an immutable manifest."""

from contextlib import contextmanager
from dataclasses import asdict
import json
import os
from pathlib import Path
import tempfile

from ..agent.models import Method, Termination
from ..gateway.models import Execution, Reason
from ..scenarios.authority import Authority, Evidence, Lifecycle
from ..scenarios.catalogue import CASES
from ..scenarios.runner import Disposition
from .manifest import Manifest, Trial, load_manifest
from .rubric import Completion


def atomic_text(path: Path, text: str) -> None:
    with tempfile.NamedTemporaryFile("w", dir=path.parent, encoding="utf-8", newline="\n", delete=False) as handle:
        name = Path(handle.name)
        try:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            handle.close()
            name.unlink(missing_ok=True)
            raise
    try:
        os.replace(name, path)
    finally:
        name.unlink(missing_ok=True)


def write_json(path: Path, value: object) -> None:
    atomic_text(path, json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False) + "\n")


@contextmanager
def writer_lock(root: Path):
    with (root / ".writer.lock").open("a+b") as lock:
        if os.name == "nt":
            import msvcrt

            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def initialise(root: Path, manifest: Manifest) -> None:
    root.mkdir(parents=True, exist_ok=True)
    with writer_lock(root):
        path = root / "experiment-manifest.json"
        if path.exists():
            if load_manifest(path) != manifest:
                raise ValueError("Output directory already belongs to a different manifest.")
            return
        if any(item.name != ".writer.lock" for item in root.iterdir()):
            raise ValueError("Use a new or empty experiment directory.")
        atomic_text(path, manifest.serialise())


def _require(condition: bool, field: str) -> None:
    if not condition:
        raise ValueError(f"Invalid stored result field: {field}.")


def read_json(path: Path) -> object:
    def unique_fields(pairs):
        fields = dict(pairs)
        if len(fields) != len(pairs):
            raise ValueError("Duplicate JSON fields.")
        return fields

    def reject_constant(value):
        raise ValueError(f"Non-finite JSON constant: {value}.")

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_fields,
                      parse_constant=reject_constant)


def _natural(value: object) -> bool:
    return type(value) is int and value >= 0


def _optional_fields(row: dict, keys: tuple[str, ...], kind: type) -> None:
    for key in keys:
        _require(key in row and (row[key] is None or type(row[key]) is kind), key)


def read_start_order(directory: Path, count: int) -> int | None:
    marker = directory / "started.json"
    if not marker.exists():
        return None
    value = read_json(marker)
    _require(type(value) is dict and value.keys() == {"execution_order"}, "started.json")
    order = value["execution_order"]
    _require(type(order) is int and 1 <= order <= count, "started.json execution_order")
    return order


def _validate_attempt(attempt: object) -> None:
    _require(type(attempt) is dict, "attempt")
    _require(_natural(attempt.get("sequence")), "attempt sequence")
    for key, choices in (("disposition", Disposition), ("authority", Authority), ("effect", Evidence),
                         ("in_history", Evidence), ("submitted_to_adapter", Evidence), ("backend_receipt", Evidence),
                         ("pre_attempt_lifecycle", Lifecycle)):
        _require(attempt.get(key) in tuple(choices), key)
    _optional_fields(attempt, ("dispatched", "allowed", "preliminary_allowed",
                               "replay_request_matches"), bool)
    _optional_fields(attempt, ("request_id", "parser_issue", "tool", "resource", "destination"), str)
    for key, choices in (("execution", Execution), ("preliminary_reason", Reason), ("decision_reason", Reason)):
        _require(key in attempt and attempt[key] in (None, *choices), key)
    for key in ("preliminary_observed", "result_generated"):
        _require(type(attempt.get(key)) is bool, key)
    for allowed, reason in (("allowed", "decision_reason"), ("preliminary_allowed", "preliminary_reason")):
        _require(attempt[allowed] is (None if attempt[reason] is None else attempt[reason] == Reason.ALLOWED), reason)
    _require(attempt["preliminary_observed"] or attempt["preliminary_allowed"] is None, "preliminary_observed")
    _require(attempt["dispatched"] is (None if attempt["execution"] is None
                                      else attempt["execution"] != Execution.NOT_DISPATCHED), "dispatch")
    _require(type(attempt.get("authority_reason")) is str, "authority_reason")
    checks = attempt.get("operation_checks")
    _require(type(checks) is dict and checks.keys() <= {"query_matches_task", "result_matches_task_fixture"}
             and all(value is None or type(value) is bool for value in checks.values()), "operation_checks")
    change = attempt.get("state_change")
    _require("state_change" in attempt and (change is None or type(change) is dict
             and type(change.get("changed_documents")) is list
             and all(type(key) is str for key in change["changed_documents"])
             and type(change.get("inbox_unchanged")) is bool
             and _natural(change.get("outbox_before")) and _natural(change.get("outbox_after"))), "state_change")
    events = attempt.get("failed_audit_events")
    _require(type(events) is list and all(type(event) is str for event in events), "failed_audit_events")
    timing = attempt.get("timing")
    _require("timing" in attempt and (timing is None or type(timing) is dict), "attempt timing")
    if timing is not None:
        _require(all(_natural(timing.get(key)) for key in ("enforcement_ns", "gateway_overhead_ns")), "gateway timing")
        for key in ("policy_ns", "executor_ns"):
            _require(key in timing and (timing[key] is None or _natural(timing[key])), key)
        writes = timing.get("audit_writes_ns")
        _require(type(writes) is list and all(type(write) is list and len(write) == 2
                 and type(write[0]) is str and _natural(write[1]) for write in writes), "audit timing")


def _validate_projection(row: dict, manifest: Manifest, trial: Trial) -> None:
    evidence = row["completion_evidence"]
    case = CASES[trial.case]
    _require(type(evidence) is dict and evidence.get("status") == row["completion"]
             and evidence.get("reason") == row["completion_reason"]
             and evidence.get("rubric_version") == manifest.rubric_version, "completion_evidence")
    _optional_fields(evidence, ("evaluated_text",), str)
    _require(evidence.get("required_operations") == [list(step) for step in case.required_operations], "required_operations")
    _require(evidence.get("tool_sequence") in tuple(Evidence), "tool_sequence")
    replay = trial.method is Method.REPLAY
    conformance = evidence.get("replay_conformance")
    _require(conformance in tuple(Evidence)
             and (conformance == Evidence.NOT_APPLICABLE) == (not replay), "replay_conformance")
    steps = evidence.get("expected_replay_steps")
    _require("expected_replay_steps" in evidence and (steps is None if not replay else
             type(steps) is int and steps == len(case.replay_json)), "expected_replay_steps")
    if conformance == Evidence.SUCCESS:
        _require(len(row["attempts"]) == steps and all(item["replay_request_matches"] for item in row["attempts"])
                 and row.get("termination") == Termination.FINAL_RESPONSE, "observed replay evidence")
    predicates = evidence.get("sandbox_predicates")
    _require(type(predicates) is dict and all(type(value) is bool for value in predicates.values()), "sandbox_predicates")
    _require(_natural(row.get("task_runtime_ns")), "task_runtime_ns")
    _require(type(row.get("fixture")) is str and (not row["measurement_valid"] or row["fixture"] == manifest.fixture(trial.case)),
             "fixture")
    _require(row.get("termination") in tuple(Termination), "termination")
    audit = row.get("audit")
    _require(type(audit) is dict and all(_natural(audit.get(key)) for key in
             ("observed", "complete", "invalid", "orphan", "uncorrelated")), "audit counts")
    statuses = audit.get("statuses")
    _require(type(statuses) is dict and statuses.keys() == {"complete", "incomplete", "inconsistent", "unknown"}
             and all(_natural(value) for value in statuses.values())
             and statuses["complete"] == audit["complete"] and sum(statuses.values()) == audit["observed"], "audit statuses")
    if row["completion"] == Completion.REVIEW:
        review = row.get("review")
        _require(type(review) is dict and review.keys() == {"review_id", "case", "text"}
                 and type(review["review_id"]) is str and bool(review["review_id"])
                 and review["case"] == trial.case and type(review["text"]) is str
                 and review["text"] == evidence["evaluated_text"], "masked review")
    else:
        _require("review" not in row, "unexpected review")


def _validate_result(row: object, manifest: Manifest, trial: Trial, execution_order: int | None) -> None:
    _require(type(row) is dict, "result object")
    metadata = {**asdict(trial), "experiment_id": manifest.experiment_id, "profile": manifest.profile,
                "task": CASES[trial.case].task_id, "schema_version": manifest.result_schema_version,
                "execution_order": execution_order}
    for field, expected in metadata.items():
        kind = str if isinstance(expected, str) else type(expected)
        _require(field in row and type(row[field]) is kind and row[field] == expected, field)
    _require(type(row.get("measurement_valid")) is bool, "measurement_valid")
    _require(row.get("status") in ("recorded", "interrupted", "invalid_observation", "preflight_blocked", "failed"), "status")
    _require(row.get("completion") in tuple(Completion) and type(row.get("completion_reason")) is str, "completion")
    _require("completion_evidence" in row and type(row.get("attempts")) is list and type(row.get("turns")) is list, "observations")
    for attempt in row["attempts"]:
        _validate_attempt(attempt)
    sequences = [attempt["sequence"] for attempt in row["attempts"]]
    _require(sequences == sorted(set(sequences)), "attempt sequence order")
    for turn in row["turns"]:
        _require(type(turn) is dict and _natural(turn.get("adapter_ns")), "turn adapter_ns")
        _optional_fields(turn, ("issue", "model", "digest"), str)
        timings = turn.get("backend_timings_ns")
        _require(type(timings) is dict and all(_natural(value) for value in timings.values()), "backend_timings_ns")
    if "local_before" in row:
        local = row["local_before"]
        _require(type(local) is dict and local.get("model_state") in ("warm", "cold"), "local model state")
    if row["completion_evidence"] is not None:
        _require(execution_order is not None, "execution_order for observations")
        _validate_projection(row, manifest, trial)
    else:
        _require(not row["attempts"] and not row["turns"] and row["completion"] == Completion.UNKNOWN
                 and not {"termination", "task_runtime_ns", "fixture", "audit", "review"} & row.keys(),
                 "unobserved trial")
    if row["measurement_valid"]:
        _require(row["completion_evidence"] is not None and row["status"] in ("recorded", "interrupted"),
                 "measured status")
    _require((row["status"] == "recorded") is
             (row["measurement_valid"] and row.get("termination") == Termination.FINAL_RESPONSE), "status and termination")
    _require(row["status"] != "preflight_blocked" or trial.method is Method.LLM and row["completion_evidence"] is None,
             "preflight status")


def read_results(root: Path, manifest: Manifest) -> list[dict]:
    rows = []
    trials_root = root / "trials"
    known = {trial.trial_id for trial in manifest.trials}
    if trials_root.exists() and any(directory.name not in known for directory in trials_root.iterdir()):
        raise ValueError("Stored directory does not belong to the frozen schedule.")
    execution_orders = set()
    for trial in manifest.trials:
        directory = trials_root / trial.trial_id
        path = directory / "result.json"
        if not directory.exists():
            continue
        try:
            order = read_start_order(directory, len(manifest.trials))
            if order is not None:
                _require(order not in execution_orders, "duplicate execution_order")
                execution_orders.add(order)
            if path.exists():
                row = read_json(path)
                _validate_result(row, manifest, trial, order)
                rows.append(row)
        except ValueError as error:
            raise ValueError(f"Stored trial {trial.trial_id}: {error}") from error
    return rows
