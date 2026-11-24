# Threat model

The system evaluates whether a trusted authorisation boundary limits unauthorised effects when an AI agent follows untrusted instructions. All resources and attack fixtures belong to the isolated local environment. The boundaries below describe the proposed architecture. Phase 1 evaluates policy decisions on synthetic records and has no model or live execution boundary. [System design](system-design.md)

## Assets

| Asset | Security property |
| --- | --- |
| Protected documents | Confidentiality of reads and integrity of document writes and deletions |
| Synthetic confidential information | Restricted exposure of invented financial figures and salary data. Preserve the distinction between a granted read and permission to transmit its contents |
| Simulated emails | Inbox confidentiality, outbox integrity and use of only the delegated simulator route in System C |
| Human and agent identities | Authentic binding of each principal to the current session and prevention of model-controlled substitutions |
| Task delegation records | Integrity of the approved scope, identity bindings, version, validity and lifecycle state |
| Security policies | Integrity and provenance of grants, predicates, tool mappings and policy mode |
| Audit logs | Integrity, completeness and correlation of decisions, safe canonical arguments, dispatches and outcomes without storing protected contents |
| Integrity of sandbox resources | Correct fixture initialisation, no unauthorised mutations and isolation across trials |

## Threat actors

An untrusted participant can supply natural-language instructions directly. A fixture author can control an ingested document or email. A content source can influence data returned by a tool even when the tool implementation is trusted. These actors can try to steer the agent outside its delegated task, change its answer, or influence what it passes to another permitted operation. Some actors may use a valid synthetic session. Authentication establishes principal identity. Every operation still requires authorisation under the selected policy.

## Attack categories

| Category | Objective | Preconditions | Potential consequences | Relevant controls | Residual risk |
| --- | --- | --- | --- | --- | --- |
| Direct Prompt Injection | Redirect the agent through instructions in a human message | The attacker can influence a message read by the model | Out-of-scope proposals, altered answers or task abandonment | Trusted context binding, per-call enforcement, separate presentation of runtime task and user content | The model may produce misleading text or propose a harmful action within scope |
| Indirect Prompt Injection | Redirect the agent through a document, email or tool result | The model receives attacker-influenced content | Out-of-scope requests or contamination of summaries and outputs | Treat results as data, authorise all subsequent requests independently and scope reads and search | Allowed reads can still deliver injected content that changes model behaviour |
| Unauthorised Resource Access | Obtain a named protected document or mailbox outside the grants | The agent can propose a recognised read or search | Disclosure of content or resource information | Exact resource pairs, read grant for search, no denied-result metadata | A legitimately readable source may carry sensitive material elsewhere |
| Data Exfiltration | Transfer synthetic confidential information to an unintended recipient or output | The agent sees data and can propose an output operation | Content reaches the wrong simulated destination or is disclosed in a permitted output | Limit read scope, output resources and exact mail routes, bind final output to the session | Authorised text and destinations can still carry inappropriate content without information-flow enforcement |
| Unauthorised Modification | Change an existing document outside the task | A registered edit target exists and the model can request an edit | Loss of integrity, misleading reports or changed future inputs | Exact edit grants, argument validation and atomic writes | An allowed edit can be inaccurate or malicious |
| Destructive Actions | Remove content beyond the approved scope | A seeded target exists and deletion is available in the tool registry | Loss of synthetic records or broken tasks | Explicit delete grant, exact target and sandbox isolation | An authorised deletion may remove material the human still needs |
| Privilege Escalation Attempts | Expand or replace the current delegation or policy | The actor can induce instructions or requests claiming wider authority | Broader actions if the control plane accepts those claims | Trusted delegation manager, no model-facing grant tools, exact request schema and immutable execution binding | Incorrect trusted provisioning or overly broad legitimate grants can still expose resources |
| Identity Spoofing Attempts | Have the gateway use a different human or agent identity | The attacker can insert identity claims into text or proposed arguments | Evaluation against a more privileged principal if context is misbound | Trusted session and agent assignment, reject identity override fields, match delegation bindings | Ambiguous text may convince the model or a human. Authentication compromise is outside scope |
| Goal Hijacking | Replace the legitimate objective or suppress completion | The model can be influenced by untrusted inputs | Misleading summaries, irrelevant output or incomplete work | Narrow permissions and independently defined task completion checks | Authorisation cannot establish that an answer serves the intended objective |
| Tool Misuse | Use a real tool with an out-of-scope target or argument, or misuse an allowed operation | The model can submit requests to a registered tool | Misdelivery, corrupted output or unexpected effects | Registry mapping, canonical arguments, exact targets and destination predicates | Free-text arguments can be semantically inappropriate while meeting the schema and policy |
| Excessive Agency | Exploit broad privileges or repeated autonomy to cause unnecessary actions | A policy has broad grants or the run allows many requests | More unauthorised effects, resource use or repeated permitted effects | Least privilege, task lifecycle, bounded run budgets and the T4 single-send constraint | Repeated requests can still consume resources within a run or across runs |

The categories overlap. For example, indirect injection can induce a data-exfiltration attempt. Classify the source of manipulation separately from the requested operation and the observed effect. [Experimental scenarios](experimental-design.md#scenario-plan)

## Trust boundaries

| Boundary | Trusted side | Untrusted inputs crossing it |
| --- | --- | --- |
| Session and delegation | Trusted application runtime, identity stores, task delegation manager and verified identifiers | Human task text, natural-language claims about identity and authority, model suggestions about scope |
| Inference exchange | Trusted runtime and model adapter, with explicit backend configuration and approved synthetic inputs | Local or hosted model responses, including proposed operations |
| Model to application | Gateway, validator, tool registry, policy engine and policy store | Raw LLM-generated tool requests and final model text |
| Executor to resources | Private tool executor, the resource catalogue, scoped storage interface and sandbox integrity | Document and email contents and external tool results represented by controlled fixtures |
| Application to evaluation | Audit logger, fixture manifests and evaluator's independent observations | Any content derived from model output or sources, even when carried in a trusted event stream |

The Human and Agent Identity Stores, Policy Store, Trusted Runtime, Model Adapter, Task Delegation Manager, Authorisation Gateway and Tool Executor form part of the trusted computing base. The model backend cannot call the executor or read the private stores or resource handles. The runtime may deliver selected, authorised tool results as untrusted input. Systems A and B share the same execution boundary while applying broader policies. [Trust boundary diagram](system-design.md#trust-boundaries)

## Assumptions

- The attacker cannot directly compromise the trusted execution environment, alter trusted policy or resource catalogue records, forge authenticated identities, or bypass the gateway.
- Tool implementations and runtime-owned metadata are trusted. An attacker may influence their returned content through synthetic inputs.
- Trusted configuration selects the policy mode, grants, fixture records and runtime context. The LLM may follow malicious instructions and can propose any model-visible tool call.
- Identity spoofing in this study means model-generated or natural-language claims and attempted payload overrides. Successful compromise of authentication falls outside the study.
- Enterprise resources and simulated actions stay local and isolated. Simulated send writes only to the outbox. The configured adapter can use a local model or an explicitly enabled hosted model under the synthetic-only data-handling rules. The model receives only approved synthetic inputs and permitted synthetic results and has no direct execution, network or filesystem tool. [Model adapter](system-design.md#model-adapter)

## Out of scope

- Full operating system compromise and direct compromise of the trusted runtime.
- Malicious LLM providers and malicious tool implementations.
- Cryptographic identity infrastructure, production IAM integration and OAuth/OIDC implementation.
- Complex multi-agent delegation and general-purpose prompt injection detection.
- Attacks against real external systems, real email delivery, production accounts and real confidential or personal data.

## Residual risks and limitations

Task-scoped authorisation bounds certain operations and targets. A manipulated agent may still perform harmful actions within scope or submit repeated requests, reducing availability even with bounded trials. An allowed summary may omit or distort facts. An allowed write or send can satisfy every structural check while misusing permitted semantics. A permitted session response, document or mail route can leak information that the policy does not track through transformations. Additional provenance or information-flow controls would be required to reason about those cases. The planned experiments measure the specified effects in this synthetic setting. [Access-control model](access-control.md) · [Experimental design](experimental-design.md)
