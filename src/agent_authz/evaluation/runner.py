"""Sequential execution of frozen supported trials with independent projections."""

from dataclasses import asdict, replace
import json
from pathlib import Path
from uuid import uuid4

from ..agent.models import Method, Termination
from ..agent.ollama import OllamaAdapter
from ..scenarios.runner import ScenarioResult, run_scenario
from .local import LocalBlocked, inspect_local
from .manifest import CONTEXT_LENGTH, MODEL_DIGEST, MODEL_TAG, Manifest, Trial, load_manifest
from .rubric import Completion, assess_completion
from .store import write_json, writer_lock


def _project(result: ScenarioResult, row: dict) -> None:
    assessment = assess_completion(result)
    row.update(termination=result.run.termination, completion=assessment.status, completion_reason=assessment.reason,
               fixture=result.fingerprint, task_runtime_ns=result.run.elapsed_ns)
    if assessment.review_text is not None:
        row["review"] = {"review_id": uuid4().hex, "case": result.case.case_id, "text": assessment.review_text}
    audit = result.audit
    if audit is not None:
        row["audit"] = {"complete": audit.numerator, "observed": audit.denominator, "invalid": audit.invalid_records,
                        "orphan": len(audit.orphan_lines), "uncorrelated": len(audit.uncorrelated_lines),
                        "statuses": audit.counts, "issues": audit.issue_counts}
    observations = {call.sequence: call for turn in result.run.turns for call in turn.calls}
    row["turns"] = [{"adapter_ns": turn.adapter_ns, "backend_timings_ns": dict(turn.backend_timings_ns),
                     "issue": turn.issue, "model": turn.model, "digest": turn.digest}
                    for turn in result.run.turns]
    for attempt in result.attempts:
        call = observations[attempt.sequence]
        gateway = call.gateway
        invocation = attempt.invocation
        row["attempts"].append({
            "sequence": attempt.sequence, "request_id": attempt.request_id, "disposition": attempt.disposition,
            "parser_issue": call.parser_issue, "authority": attempt.authority.authority,
            "authority_reason": attempt.authority.reason, "pre_attempt_lifecycle": attempt.pre_attempt_lifecycle,
            "tool": invocation.tool if invocation else None, "resource": invocation.resource_id if invocation else None,
            "destination": dict(invocation.arguments).get("destination") if invocation else None,
            "allowed": attempt.final_allowed, "decision_reason": gateway.decision.reason if gateway else None,
            "dispatched": attempt.dispatched, "execution": attempt.execution, "effect": attempt.effect,
            "result_generated": call.model_result_json is not None, "in_history": attempt.in_history,
            "submitted_to_adapter": attempt.submitted_to_adapter, "backend_receipt": attempt.backend_receipt,
            "timing": asdict(gateway.timing) if gateway else None,
            "failed_audit_events": gateway.failed_audit_events if gateway else (),
        })


def _initial_row(manifest: Manifest, trial: Trial) -> dict:
    return {**asdict(trial), "experiment_id": manifest.experiment_id, "profile": manifest.profile,
            "task": "T" + trial.case[1:], "schema_version": 1, "status": "interrupted",
            "measurement_valid": False, "completion": Completion.UNKNOWN, "attempts": [], "turns": []}


def execute_trials(root: Path, manifest: Manifest, methods: frozenset[Method], *, confirm_local_only: bool = False) -> int:
    if Method.LLM in methods and not confirm_local_only:
        raise ValueError("Explicit local-only confirmation is required.")
    count = 0
    with writer_lock(root):
        if load_manifest(root / "experiment-manifest.json") != manifest:
            raise ValueError("Stored manifest differs from execution request.")
        trials_root = root / "trials"
        trials_root.mkdir(exist_ok=True)
        order = sum((trials_root / trial.trial_id).exists() for trial in manifest.trials)
        for trial in manifest.trials:
            if trial.method not in methods:
                continue
            directory = trials_root / trial.trial_id
            final = directory / "result.json"
            if final.exists():
                continue
            row = _initial_row(manifest, trial)
            try:
                directory.mkdir()
            except FileExistsError:
                marker = directory / "started.json"
                if marker.exists():
                    row["execution_order"] = json.loads(marker.read_text(encoding="utf-8"))["execution_order"]
                row["issue"] = "interrupted_before_persistence"
                write_json(final, row)
                continue
            count += 1
            order += 1
            row["execution_order"] = order
            write_json(directory / "started.json", {"execution_order": order})
            adapter = None
            try:
                if trial.method is Method.LLM:
                    row["local_before"] = inspect_local()
                    adapter = OllamaAdapter(MODEL_TAG, expected_digest=MODEL_DIGEST, context_length=CONTEXT_LENGTH,
                                            confirm_local_only=confirm_local_only)
                result = run_scenario(trial.case, trial.policy, trial.method, limits=manifest.limits,
                                      settings=replace(manifest.settings, seed=trial.seed),
                                      local_adapter=adapter, audit_path=directory / "audit.jsonl")
                _project(result, row)
                valid = result.fingerprint == manifest.fixture(trial.case)
                if adapter is not None:
                    row["local_after"] = inspect_local(require_headroom=False)
                    valid &= row["local_after"]["context_length"] == CONTEXT_LENGTH and all(
                        turn.model == MODEL_TAG and turn.digest == MODEL_DIGEST for turn in result.run.turns)
                    valid &= bool(result.run.turns)
                row["measurement_valid"] = valid
                row["status"] = "recorded" if valid and result.run.termination is Termination.FINAL_RESPONSE else (
                    "interrupted" if valid else "invalid_observation"
                )
            except LocalBlocked as error:
                row.update(status="preflight_blocked" if "termination" not in row else "invalid_observation",
                           issue=str(error))
                write_json(final, row)
                break  # Do not launch subsequent trials against the unavailable configuration.
            except Exception as error:
                row["issue"] = type(error).__name__
                write_json(final, row)
                raise
            write_json(final, row)
    return count
