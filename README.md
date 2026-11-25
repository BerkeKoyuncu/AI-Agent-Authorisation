# AI Agent Authorisation Under Prompt Injection

CENG374 — Introduction to Computer Security | Gazi University, Department of Computer Engineering

This research prototype studies tool-use authorisation for AI agents that may follow untrusted instructions.

**Research question.** Does independent, identity- and task-scoped authorisation reduce unauthorised tool effects under prompt injection, compared with broad static permissions and a fixed tool allowlist, while preserving legitimate task completion?

The gateway evaluates each requested action independently of any model. Under the scoped policy it uses the authenticated human, assigned agent and active task authority supplied by the trusted runtime.

## Current status

- **Phase 1 implemented.** Immutable records model synthetic identities, permissions, delegation and requests. A deterministic policy function checks identity/task binding and the intersection of exact action-resource grants. The demo reports decisions and the unit suite checks representative cases.
- **Phase 2 design complete.** The architecture, threat model, access-control fixtures and evaluation protocol define the planned prototype.
- **Phase 3 implemented.** A resettable in-memory sandbox provides a fixed synthetic catalogue and seven trusted document and simulated mail handlers.
- **Phase 4 implemented.** Trusted synthetic identities, authenticated sessions, agent assignment and task delegation are available.
- **Phase 5 implemented.** The gateway validates and mediates seven sandbox tools under the three comparison policies, with final admission checks and a local audit journal. Model integration, broader audit analysis and experiments remain planned.

## Design documentation

- [System design and Phase 1 review](docs/system-design.md)
- [Threat model](docs/threat-model.md)
- [Access-control model](docs/access-control.md)
- [Experimental design](docs/experimental-design.md)
- [Sandbox implementation](docs/sandbox-design.md)
- [Identity and delegation implementation](docs/identity-delegation-design.md)
- [Authorisation gateway implementation](docs/gateway-design.md)
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
python -m agent_authz.sandbox.demo
python -m agent_authz.identity.demo
python -m agent_authz.gateway.demo
python -m pytest -q
```

The Phase 1 demo prints preliminary authorisation decisions. The Phase 3 demo directly invokes sandbox handlers. The Phase 4 demo binds and revokes task authority. The Phase 5 demo compares admission and execution under all three policies using separate synthetic sandboxes.

## Development sequence

The first five phases are complete. The next phase is provider-independent LLM integration, followed by synthetic scenarios, broader audit logging and security testing, experimental evaluation, then the demo and final report. [Development roadmap](docs/roadmap.md#core-phases)

## Scope and safety

The authorisation boundary is intended to limit tool effects after prompt injection. Manipulated summaries, harmful behaviour within the allowed scope and leakage through permitted output channels remain possible. The evaluation uses synthetic documents, simulated mailboxes and invented identities. All resources and simulated actions stay local and isolated. The model adapter prefers local inference and allows explicitly configured hosted inference with approved synthetic inputs only. Real personal or confidential data, real email, production enterprise systems, credentials in project files or model inputs, arbitrary shell execution and unrestricted filesystem tools are outside the project scope. [Model adapter](docs/system-design.md#model-adapter)
