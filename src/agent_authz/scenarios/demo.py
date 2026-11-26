"""List the review catalogue or run one deterministic normal scenario."""

import argparse

from ..agent.models import Method
from ..gateway import PolicyMode
from .catalogue import CASES, export_manifest
from .runner import run_scenario


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    listing = parser.add_mutually_exclusive_group()
    listing.add_argument("--list", action="store_true", help="List normal cases and review specifications")
    listing.add_argument("--manifest", action="store_true", help="Print the versioned JSON manifest")
    parser.add_argument("--case", choices=tuple(CASES), default="N1")
    parser.add_argument("--policy", choices=tuple(PolicyMode), default=PolicyMode.C)
    parser.add_argument("--backend", choices=(Method.REPLAY, Method.STUB), default=Method.REPLAY)
    args = parser.parse_args()
    if args.manifest:
        print(export_manifest())
        return 0
    if args.list:
        for case in CASES.values():
            availability = ", ".join(case.methods) if case.methods else "review specification"
            print(f"{case.case_id} v{case.version} | {case.task_id} | {case.title} | {availability}")
        return 0
    if not CASES[args.case].methods:
        parser.error(f"{args.case} is a review specification. Use --manifest for its expected evidence.")

    result = run_scenario(args.case, PolicyMode(args.policy), Method(args.backend))
    print(f"{result.case.case_id} v{result.case.version} | {result.case.task_id} | "
          f"System {result.policy} | method={result.method}")
    print(f"Initial fixture {result.case.fixture} | SHA-256 {result.fingerprint}")
    for attempt in result.attempts:
        target = (f"{attempt.invocation.tool} {attempt.invocation.resource_id}"
                  if attempt.invocation is not None else "no canonical invocation")
        print(f"  Proposal {attempt.sequence} | {target} | {attempt.disposition} | "
              f"{attempt.authority.authority}")
        print(f"    Preliminary allow={attempt.preliminary_allowed} | final allow={attempt.final_allowed} | "
              f"dispatched={attempt.dispatched} | execution={attempt.execution}")
        print(f"    Effect={attempt.effect} | history={attempt.in_history} | "
              f"adapter submission={attempt.submitted_to_adapter}")
    print(f"Tool sequence={result.tool_sequence} | task completion={result.completion} | "
          f"objective={result.objective}")
    print(f"Replay conformance={result.replay_conformance} | "
          f"unauthorised attempts={len(result.unauthorised_attempts)} | "
          f"verified unauthorised effects={len(result.verified_unauthorised_effects)}")
    print(f"Termination={result.run.termination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
