# AI Agent Authorisation Under Prompt Injection

CENG374 — Introduction to Computer Security | Gazi University, Department of Computer Engineering

This research prototype studies tool-use authorisation for AI agents that may follow untrusted instructions.

**Research question.** Does independent, identity- and task-scoped authorisation reduce unauthorised tool effects under prompt injection, compared with broad static permissions and a fixed tool allowlist, while preserving legitimate task completion?

The proposed gateway evaluates each requested action independently of the LLM. It uses the authenticated human and assigned agent supplied by the trusted runtime and the active task's delegated scope.

## Current status

- **Phase 1 implemented.** Immutable records model synthetic identities, permissions, delegation and requests. A deterministic policy function checks identity/task binding and the intersection of exact action-resource grants. The demo reports decisions and the unit suite checks representative cases.
- **Phase 2 design documented.** The architecture, threat model, access-control fixtures and evaluation protocol define the planned prototype. Runtime authentication, sandbox resources, tool execution, the gateway, model integration, audit logging and experiments remain planned.

## Design documentation

- [System design and Phase 1 review](docs/system-design.md)
- [Threat model](docs/threat-model.md)
- [Access-control model](docs/access-control.md)
- [Experimental design](docs/experimental-design.md)
- [Development roadmap](docs/roadmap.md)
- [Phase 1 design notes](docs/design-notes.md)

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

The demo uses a synthetic trusted context. It prints an allowed meeting-note read and a denied out-of-task salary read. The phase-one policy returns decisions only.

## Development sequence

Foundation and design are followed by the sandbox, identity and delegation, the gateway, local LLM integration, synthetic scenarios, audit logging and security testing, experimental evaluation, then the demo and final report. The next implementation phase is the [synthetic sandbox](docs/roadmap.md#core-phases).

## Scope and safety

The authorisation boundary is intended to limit tool effects after prompt injection. Manipulated summaries, harmful behaviour within the allowed scope and leakage through permitted output channels remain possible. The evaluation is confined to local synthetic documents, simulated mailboxes and invented identities. Simulated mail is written only to a local outbox. Real personal or confidential data, real email, production systems, credentials, arbitrary shell execution and unrestricted filesystem tools are outside the project scope.
