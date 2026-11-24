# AI Agent Authorisation Under Prompt Injection

CENG374 — Introduction to Computer Security | Phase 1: Project Foundation

This research prototype investigates whether independent, identity- and task-scoped authorisation can limit the execution of unauthorised AI-agent actions under prompt injection.

## Setup

Requires Python 3.11 or newer. Create and activate a virtual environment:

```sh
python -m venv .venv
```

Windows PowerShell: `.\.venv\Scripts\Activate.ps1`  
macOS/Linux: `source .venv/bin/activate`

```sh
python -m pip install -e ".[dev]"
python -m agent_authz.demo
python -m pytest -q
```

## Phase-one scope

- Immutable domain models for synthetic identities, permissions, task delegation and requests.
- A minimal deterministic policy function and unit tests.
- Exact action-resource permissions, default deny, and identity-task binding.

This is not a complete security gateway. No actual authentication, tool execution, LLM, audit log, database, network, or attack experiments are implemented. The demo runner supplies a trusted synthetic context. Real tool requests must never be allowed to choose their own execution context.

See `docs/design-notes.md` for initial decisions and limitations.
