"""Run one normal synthetic task with an explicitly selected backend."""

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from ..gateway import PolicyMode
from ..gateway.audit import JsonlAudit
from .models import AgentError, Termination
from .ollama import OllamaAdapter
from .prompts import TASK_PROMPTS, StubAdapter, normal_replay
from .runtime import prepare_task


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("stub", "replay", "ollama"), default="stub")
    parser.add_argument("--policy", choices=tuple(PolicyMode), default=PolicyMode.C)
    parser.add_argument("--task", choices=tuple(TASK_PROMPTS), default="T1")
    parser.add_argument("--model", help="Installed Ollama model, with an optional local tag")
    parser.add_argument("--confirm-local-only", action="store_true", help="Confirm that the local server has cloud disabled")
    parser.add_argument("--show-denial", action="store_true", help="Use the scripted T1 denial demonstration")
    args = parser.parse_args()
    if args.backend == "ollama" and (not args.model or not args.confirm_local_only):
        parser.error("Ollama requires --model and --confirm-local-only")
    if args.backend != "ollama" and (args.model or args.confirm_local_only):
        parser.error("Local model options require --backend ollama")
    if args.show_denial and (args.backend != "stub" or args.task != "T1"):
        parser.error("The scripted denial demonstration requires --backend stub --task T1")

    try:
        if args.backend == "ollama":
            adapter = OllamaAdapter(args.model, confirm_local_only=args.confirm_local_only)
        elif args.backend == "replay":
            adapter = normal_replay(args.task)
        else:
            adapter = StubAdapter(args.task, show_denial=args.show_denial)
        print(f"Synthetic task {args.task} | System {args.policy} | method={adapter.backend.method}")
        if adapter.backend.model:
            print(f"Requested local model: {adapter.backend.model}")
        with TemporaryDirectory(prefix="agent-authz-phase6-") as directory:
            task = prepare_task(args.task, PolicyMode(args.policy), JsonlAudit(Path(directory) / "audit.jsonl"))
            result = task.runtime.run(adapter)
    except AgentError as error:
        print(f"Run setup rejected: {error.issue}")
        return 2

    for turn in result.turns:
        if turn.model:
            print(f"Observed model turn {turn.number}: {turn.model}")
        if turn.issue:
            print(f"Turn {turn.number} issue: {turn.issue}")
        for call in turn.calls:
            print(f"  proposal {call.sequence}: {call.proposal_json or '[omitted]'}")
            if call.gateway is not None:
                decision = "allow" if call.gateway.decision.allowed else "deny"
                print(f"    {decision}, dispatched={call.gateway.dispatched}, execution={call.gateway.execution}")
            elif call.unprocessed is not None:
                print(f"    unprocessed: {call.unprocessed}")
            if call.parser_issue:
                print(f"    parser issue: {call.parser_issue}")
    if result.final_response is not None:
        print(f"Final response: {json.dumps(result.final_response, ensure_ascii=True)}")
    print(f"Termination: {result.termination}")
    return 0 if result.termination is Termination.FINAL_RESPONSE else 1


if __name__ == "__main__":
    raise SystemExit(main())
