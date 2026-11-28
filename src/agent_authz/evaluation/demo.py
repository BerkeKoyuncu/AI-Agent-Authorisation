"""Offline-first command line for normal evaluation infrastructure."""

import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess

from ..agent.models import Method
from .manifest import load_manifest, make_manifest, make_schedule
from .report import export_permissions, export_results, import_reviews
from .runner import execute_trials
from .store import initialise, read_results, write_json, writer_lock


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def _check_revision(revision: str) -> None:
    if _git("rev-parse", "HEAD") != revision or _git("status", "--porcelain=v1"):
        raise ValueError("The checked-out revision must match the manifest and the worktree must be clean.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    schedule = commands.add_parser("schedule")
    schedule.add_argument("--profile", choices=("experiment", "validation", "pilot"), default="experiment")
    for action in ("manifest", "freeze", "offline", "permission", "aggregate", "review-export", "review-import", "pilot", "run"):
        sub = commands.add_parser(action, aliases=["resume"] if action == "run" else [])
        sub.add_argument("output", type=Path)
        if action in {"freeze", "offline", "pilot"}:
            sub.add_argument("--id", required=True)
        if action == "freeze":
            sub.add_argument("--profile", choices=("experiment", "validation", "pilot"), default="experiment")
        if action == "review-import":
            sub.add_argument("decisions", type=Path)
        if action in {"pilot", "run"}:
            sub.add_argument("--confirm-local-only", action="store_true")
        if action == "run":
            sub.add_argument("--method", choices=("all", "offline", "replay", "stub", "llm"), default="offline")
            sub.add_argument("--approve-live-matrix", action="store_true")
    args = parser.parse_args()
    if args.command in (None, "schedule"):
        trials = make_schedule(getattr(args, "profile", "experiment"))
        if args.command == "schedule":
            for row in trials:
                print(f"{row.order:3} {row.trial_id} seed={row.seed}")
        print(f"Planned normal trials: {len(trials)} ({dict(Counter(str(row.method) for row in trials))}).")
        print("42 X-case replay combinations unsupported. ASR and attacker-objective rates are N/A.")
        return 0

    root = args.output.resolve()
    repository = Path(_git("rev-parse", "--show-toplevel")).resolve()
    if root.is_relative_to(repository):
        parser.error("Choose an output directory outside the repository.")
    try:
        if args.command in {"freeze", "offline", "pilot"}:
            if args.command == "pilot" and not args.confirm_local_only:
                raise ValueError("Explicit local-only confirmation is required.")
            revision = _git("rev-parse", "HEAD")
            _check_revision(revision)
            profile = {"offline": "validation", "pilot": "pilot"}.get(args.command, getattr(args, "profile", "experiment"))
            manifest = make_manifest(args.id, revision, profile)
            initialise(root, manifest)
        else:
            manifest = load_manifest(root / "experiment-manifest.json")
        if args.command == "manifest":
            print(manifest.serialise(), end="")
            return 0
        if args.command == "freeze":
            print(f"Frozen {len(manifest.trials)} trials at {root}.")
            return 0
        if args.command == "permission":
            _check_revision(manifest.code_revision)
        if args.command in {"offline", "pilot", "run", "resume"}:
            _check_revision(manifest.code_revision)
            selection = getattr(args, "method", "llm" if args.command == "pilot" else "offline")
            methods = {
                "offline": frozenset({Method.REPLAY, Method.STUB}),
                "all": frozenset(trial.method for trial in manifest.trials),
            }.get(selection)
            if methods is None:
                methods = frozenset({Method(selection)})
            if not any(trial.method in methods for trial in manifest.trials):
                raise ValueError("Selected methods are absent from the frozen schedule.")
            if Method.LLM in methods and manifest.profile == "experiment" and not args.approve_live_matrix:
                raise ValueError("The measured live matrix requires explicit approval.")
            count = execute_trials(root, manifest, methods,
                                   confirm_local_only=getattr(args, "confirm_local_only", False))
            print(f"Started {count} new trials.")
        with writer_lock(root):
            if args.command == "review-import":
                print(f"Imported {import_reviews(root, read_results(root, manifest), args.decisions)} reviews.")
            if args.command in {"permission", "offline"}:
                print(f"Assessed {export_permissions(root, manifest)} permission candidates without dispatch.")
                write_json(root / "control-evidence.json", {
                    "category": "gateway_regression",
                    "source": "tests/test_gateway.py::test_approved_comparison_cases",
                    "expected_parameterisations": 39, "structured_metric_observations": None,
                    "limitation": "Direct gateway controls are separate from scenario and LLM measurements.",
                })
            if args.command != "permission":
                export_results(root, manifest)
        observed = read_results(root, manifest)
        print(f"Trial outcomes: {json.dumps(Counter(row['status'] for row in observed), sort_keys=True)}.")
        print(f"Outputs: {root}")
        return 1 if args.command in {"offline", "pilot", "run", "resume"} and any(
            row["status"] == "preflight_blocked" for row in observed if row["method"] in methods
        ) else 0
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
