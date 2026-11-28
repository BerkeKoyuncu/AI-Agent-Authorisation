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
- **Phase 5 implemented.** The gateway validates and mediates seven sandbox tools under the three comparison policies, with final admission checks and a local audit journal.
- **Phase 6 implemented.** The provider-independent conversation loop supports deterministic replay, a scripted stub and opt-in local Ollama. A live local T1 smoke test passed under System C. [Integration evidence](docs/evaluation-implementation.md#integration-smoke-test)
- **Phase 7 revised control-validation scope complete.** The six normal cases run under all three policies with replay and stub. The 20-case evidence matrix links gateway and runtime regressions and passive reviews. All 42 X-case replay combinations remain unsupported. [Evidence matrix and open criteria](docs/attack-scenarios.md#case-to-evidence-traceability)
- **Phase 8 implemented.** Versioned JSONL audit records use an allowlisted schema. The bounded reader independently correlates persisted records with observed gateway attempts and reports incomplete or conflicting evidence. [Audit validation design](docs/audit-security-design.md)
- **Phase 9 infrastructure implemented.** The evaluator freezes normal-task schedules, persists resumable results, supports masked semantic review, and exports non-dispatch permissions, completeness and timings. Measured live trials remain pending. [Evaluation implementation](docs/evaluation-implementation.md)

## Design documentation

- [System design and Phase 1 review](docs/system-design.md)
- [Threat model](docs/threat-model.md)
- [Access-control model](docs/access-control.md)
- [Experimental design](docs/experimental-design.md)
- [Sandbox implementation](docs/sandbox-design.md)
- [Identity and delegation implementation](docs/identity-delegation-design.md)
- [Authorisation gateway implementation](docs/gateway-design.md)
- [Model adapter and runtime implementation](docs/llm-integration-design.md)
- [Scenario specifications and control validation](docs/attack-scenarios.md)
- [Audit logging and security validation](docs/audit-security-design.md)
- [Normal evaluation protocol v1](docs/evaluation-protocol-v1.md)
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
python -m agent_authz.agent.demo
python -m agent_authz.scenarios.demo
python -m agent_authz.audit.demo
python -m agent_authz.evaluation.demo
python -m pytest -q
```

The Phase 1 demo prints preliminary authorisation decisions. The Phase 3 demo directly invokes sandbox handlers. The Phase 4 demo binds and revokes task authority. The Phase 5 demo compares admission and execution under all three policies using separate synthetic sandboxes.

The Phase 6 demo defaults to the offline stub. Use `python -m agent_authz.agent.demo --backend replay --policy C --task T1` for deterministic replay. For an already installed local tool-capable Ollama model on a server with cloud features disabled, use `python -m agent_authz.agent.demo --backend ollama --model MODEL_NAME --confirm-local-only --policy C --task T1`. Replace `MODEL_NAME` with the installed tag. [Local backend setup and smoke-test criteria](docs/llm-integration-design.md#local-ollama-backend)

Use `python -m agent_authz.scenarios.demo --list` to see the catalogue and `python -m agent_authz.scenarios.demo --case N4 --policy C --backend stub` to see a normal case with independent evidence.

The audit demo runs one supported case with a temporary journal and reports independent attempt coverage and path-specific completeness.

## Development sequence

The roadmap records the supported scenario and audit scope, and tracks experimental evaluation and the final demonstration and report. [Development roadmap](docs/roadmap.md#core-phases)

## Scope and safety

The authorisation boundary is intended to limit tool effects after prompt injection. Manipulated summaries, harmful behaviour within the allowed scope and leakage through permitted output channels remain possible. The evaluation uses synthetic documents, simulated mailboxes and invented identities. All resources and simulated actions stay local and isolated. The shipped inference backend is explicitly configured local Ollama. Hosted inference remains an extension point. Real personal or confidential data, real email, production enterprise systems, credentials in project files or model inputs, arbitrary shell execution and unrestricted filesystem tools are outside the project scope. [Model adapter](docs/llm-integration-design.md)
