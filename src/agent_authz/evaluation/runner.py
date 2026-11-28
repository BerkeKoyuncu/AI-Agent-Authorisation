"""Sequential execution of frozen supported trials with independent projections."""

from dataclasses import asdict, replace
import json
from pathlib import Path
from uuid import uuid4

from ..agent.models import Method, Termination
from ..agent.ollama import OllamaAdapter
from ..sandbox.fixtures import AGENDA_LINE, AGENDA_QUERY, INBOX_DRAFT
from ..scenarios.evidence import final_sandbox_predicates
from ..scenarios.runner import ScenarioResult, run_scenario
from .local import LocalBlocked, inspect_local
from .manifest import CONTEXT_LENGTH, MODEL_DIGEST, MODEL_TAG, Manifest, Trial, load_manifest
from .rubric import Completion, assess_completion
from .store import read_results, read_start_order, write_json, writer_lock


def _project(result: ScenarioResult, row: dict, manifest: Manifest) -> None:
    assessment = assess_completion(result)
    row.update(termination=result.run.termination, completion=assessment.status, completion_reason=assessment.reason,
               fixture=result.fingerprint, task_runtime_ns=result.run.elapsed_ns)
    row["completion_evidence"] = {
        "rubric_version": manifest.rubric_version, "status": assessment.status, "reason": assessment.reason,
        "evaluated_text": assessment.evaluated_text, "required_operations": result.case.required_operations,
        "tool_sequence": result.tool_sequence, "replay_conformance": result.replay_conformance,
        "expected_replay_steps": len(result.case.replay_json) if result.method is Method.REPLAY else None,
        "sandbox_predicates": final_sandbox_predicates(result.case.task_id, result.before, result.after),
    }
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
    for index, attempt in enumerate(result.attempts):
        call = observations[attempt.sequence]
        gateway = call.gateway
        preliminary = gateway.preliminary if gateway else None
        invocation = attempt.invocation
        operation_checks = {}
        if invocation and invocation.tool in {"search_documents", "read_email"}:
            expected_data = [AGENDA_LINE] if invocation.tool == "search_documents" else asdict(INBOX_DRAFT)
            operation_checks["result_matches_task_fixture"] = (
                json.loads(attempt.history_content) == {"status": "ok", "data": expected_data}
                if attempt.history_content is not None else None
            )
            if invocation.tool == "search_documents":
                operation_checks["query_matches_task"] = dict(invocation.arguments)["query"] == AGENDA_QUERY
        replay_match = None
        if result.method is Method.REPLAY and attempt.gateway_input_json is not None:
            replay_match = index < len(result.case.replay_json) and attempt.gateway_input_json == result.case.replay_json[index]
        state_change = None
        if attempt.before is not None and attempt.after is not None:
            before, after = attempt.before.sandbox, attempt.after.sandbox
            state_change = {
                "changed_documents": sorted(key for key in before.documents if before.documents[key] != after.documents[key]),
                "inbox_unchanged": before.inbox == after.inbox,
                "outbox_before": len(before.outbox), "outbox_after": len(after.outbox),
            }
        row["attempts"].append({
            "sequence": attempt.sequence, "request_id": attempt.request_id, "disposition": attempt.disposition,
            "parser_issue": call.parser_issue, "authority": attempt.authority.authority,
            "authority_reason": attempt.authority.reason, "pre_attempt_lifecycle": attempt.pre_attempt_lifecycle,
            "tool": invocation.tool if invocation else None, "resource": invocation.resource_id if invocation else None,
            "destination": dict(invocation.arguments).get("destination") if invocation else None,
            "preliminary_observed": preliminary is not None,
            "preliminary_allowed": attempt.preliminary_allowed,
            "preliminary_reason": preliminary.decision.reason if preliminary and preliminary.decision else None,
            "allowed": attempt.final_allowed, "decision_reason": gateway.decision.reason if gateway else None,
            "dispatched": attempt.dispatched, "execution": attempt.execution, "effect": attempt.effect,
            "state_change": state_change,
            "operation_checks": operation_checks, "replay_request_matches": replay_match,
            "result_generated": call.model_result_json is not None, "in_history": attempt.in_history,
            "submitted_to_adapter": attempt.submitted_to_adapter, "backend_receipt": attempt.backend_receipt,
            "timing": asdict(gateway.timing) if gateway else None,
            "failed_audit_events": gateway.failed_audit_events if gateway else (),
        })


def _initial_row(manifest: Manifest, trial: Trial) -> dict:
    return {**asdict(trial), "experiment_id": manifest.experiment_id, "profile": manifest.profile,
            "task": "T" + trial.case[1:], "schema_version": manifest.result_schema_version,
            "status": "interrupted", "execution_order": None, "measurement_valid": False,
            "completion": Completion.UNKNOWN, "completion_reason": "assessment unavailable",
            "completion_evidence": None, "attempts": [], "turns": []}


def execute_trials(root: Path, manifest: Manifest, methods: frozenset[Method], *, confirm_local_only: bool = False) -> int:
    if Method.LLM in methods and not confirm_local_only:
        raise ValueError("Explicit local-only confirmation is required.")
    count = 0
    with writer_lock(root):
        if load_manifest(root / "experiment-manifest.json") != manifest:
            raise ValueError("Stored manifest differs from execution request.")
        trials_root = root / "trials"
        trials_root.mkdir(exist_ok=True)
        recorded = {row["trial_id"] for row in read_results(root, manifest)}
        order = sum((trials_root / trial.trial_id).exists() for trial in manifest.trials)
        for trial in manifest.trials:
            if trial.method not in methods:
                continue
            directory = trials_root / trial.trial_id
            final = directory / "result.json"
            if trial.trial_id in recorded:
                continue
            row = _initial_row(manifest, trial)
            try:
                directory.mkdir()
            except FileExistsError:
                row["execution_order"] = read_start_order(directory, len(manifest.trials))
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
                projection = {**row, "attempts": []}
                _project(result, projection, manifest)
                row = projection
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
                row.update(status="failed", issue=type(error).__name__, measurement_valid=False)
                write_json(final, row)
                raise
            write_json(final, row)
    return count
