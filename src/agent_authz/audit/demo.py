"""Persist and independently check the audit journal of one offline normal case."""

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory

from ..agent.models import Method
from ..gateway import PolicyMode
from ..scenarios.catalogue import CASES
from ..scenarios.runner import run_scenario


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=[case.case_id for case in CASES.values() if case.methods], default="N4")
    parser.add_argument("--policy", choices=tuple(PolicyMode), default=PolicyMode.C)
    parser.add_argument("--backend", choices=(Method.REPLAY, Method.STUB), default=Method.REPLAY)
    options = parser.parse_args()
    with TemporaryDirectory(prefix="agent-authz-phase8-") as directory:
        result = run_scenario(options.case, options.policy, options.backend, audit_path=Path(directory) / "audit.jsonl")
    assessment = result.audit
    assert assessment is not None
    print(f"Scenario {result.case.case_id} | System {result.policy} | method={result.method}")
    print(f"Observed gateway attempts={assessment.denominator} | persisted valid records={len(assessment.journal.records)}")
    for attempt in assessment.attempts:
        names = ", ".join(row.event for row in attempt.records) or "none"
        print(f"  Attempt {attempt.observation.sequence} | {attempt.status} | {names}")
        for problem in attempt.problems:
            print(f"    {problem.issue}" + (f" ({problem.event})" if problem.event else ""))
    for problem in assessment.journal.problems:
        print(f"  Journal {problem.issue}" + (f" (line {problem.line})" if problem.line is not None else ""))
    print(f"Completeness {assessment.numerator}/{assessment.denominator}" +
          (" (N/A)" if assessment.fraction is None else ""))
    print(f"Invalid records={assessment.invalid_records} | orphan records={len(assessment.orphan_lines)} | "
          f"uncorrelated records={len(assessment.uncorrelated_lines)}")
    return 0 if assessment.globally_clean and assessment.denominator else 1


if __name__ == "__main__":
    raise SystemExit(main())
