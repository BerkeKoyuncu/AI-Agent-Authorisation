# Phase 8 audit completeness and security validation

The checker compares a local JSON Lines journal with an independently captured inventory of calls that reached the gateway. It preserves the difference between a proposal, a structural verdict, preliminary permission, provisional intent, final admission, actual dispatch, executor outcome, independently observed effect and task lifecycle. Completeness describes the evidence for an attempt. A complete record can describe a denial, a known executor failure or an uncertain mutation outcome. [Approved definitions](experimental-design.md#metrics-and-units) · [Threat model](threat-model.md#trust-boundaries)

## Version 1 schema

Every record supplies the following fields. `schema_version` is integer `1`, independent of the policy version, currently `phase5-v1`. Request and binding identifiers are bounded opaque strings. Version numbers are positive integers where available. Timing values are nonnegative integer nanoseconds below 2⁶³. Nullable fields use JSON `null` as specified below.

| Fields on every event | Validation and source |
| --- | --- |
| `schema_version`, `event`, `request_id` | Known format and event name. Gateway-generated request ID with an opaque namespace and sequence, or a standalone opaque ID. |
| `timestamp`, `policy_mode`, `policy_version` | UTC ISO timestamp, trusted A/B/C mode and a bounded policy version label. |
| `policy_ns`, `enforcement_ns`, `executor_ns` | Policy duration on every record. Enforcement duration begins appearing at admission. Executor duration appears on dispatched attempts at admission and later. Earlier or inapplicable values are null. |
| `prior_audit_writes_ns` | Ordered pairs of known event names and elapsed nanoseconds for earlier write attempts, including failures. The current event's duration is unavailable at serialization. |

The operation group `tool`, `action`, `resource_id` appears together only after structural validation. The shared tool registry and resource catalogue constrain these values. A canonical send also requires an exact registered `destination`. A route rejected by task policy can still appear because it was structurally valid. An unvalidated operation omits the entire group.

The binding group `run_id`, `session_id`, `human_id`, `agent_id` appears together for registered run provenance. Provenance can still be known after validity ends. The schema restricts human and agent IDs to the synthetic principal catalogue. `task_id` and `delegation_id` appear together when System C has established the relevant task record. Omission indicates unavailable provenance or scope. The reader checks record structure. Independent trusted observations substantiate correlation and identities.

| Event | Additional fields and conditions |
| --- | --- |
| `attempt` | Common fields and only applicable metadata groups. |
| `validation` | Boolean `valid` and `reason`. Success requires canonical operation metadata and a null reason. Failure requires a safe validation reason and omits the operation. |
| `preliminary` | Boolean `allowed`, enumerated `reason`, and nullable `human_version`, `agent_version`, `delegation_version`. Canonical operation is required. An allowance requires registered binding and both principal versions, plus the delegation version in System C. A known delegation version requires the corresponding scope group. |
| `dispatch_intent` | Decision fields as above, `allowed=true`, and `provisional=true`. |
| `admission` | Decision fields as above. A denial requires `dispatched=false`. An allowance requires registered binding and canonical operation and leaves dispatch to its own event. |
| `dispatch` | `dispatched=true`, with registered binding and canonical operation. |
| `outcome` | `execution` is `succeeded`, `failed` or `unknown`. `reason` is null for success, a sandbox error code for known failure or `EXECUTOR_ERROR` for uncertainty. Binding and operation are required. |
| `lifecycle` | `status` and boolean `reserved_send`, with binding and a canonical mutation. Known statuses are `completed`, `expired_after_effect`, `revoked_after_effect`, `completion_unavailable`, `failure_no_effect` and `quarantined`. Scope is required except for quarantine, which can occur in every mode. |

The writer validates the exact field allowlist and value domains before opening the journal. It rejects extra fields and unchecked values with fixed issue codes. Prompts, responses, document and replacement text, queries, message subjects and bodies, proofs, bearer tokens, provider data, exception details, full grants and snapshots stay out of the journal. The model receives the existing gateway projection. Unversioned journals produce `legacy_unversioned` diagnostics. Unknown schema versions are reported separately. The reader leaves the original bytes untouched. [Schema](../src/agent_authz/audit/schema.py) · [Writer](../src/agent_authz/gateway/audit.py)

## Persistence and enforcement order

`JsonlAudit` appends one UTF-8 line, flushes its buffer and calls `os.fsync` before acknowledging the write. Trusted application code supplies a path in a controlled local directory. The directory, file and process are assumed to be under trusted control. The audit path is outside the tool schemas and model context.

The gateway records the attempt, validation and preliminary verdict. It checks current authority before writing provisional intent, then checks again after persistence. The final check and applicable reservation lead directly to executor invocation. The gateway performs lifecycle handling and records admission, dispatch, outcome and any lifecycle event after return. A denial records admission with no dispatch. Phase 8 adds no callback or persistence operation between the existing final check and executor.

A required pre-dispatch persistence failure prevents execution and triggers a best-effort denial record. A post-dispatch failure preserves the actual result and effect. A failed write can leave readable bytes without confirmation. The trusted result reports such writes as failed even if the reader finds a valid record. Uncertain mutation handling continues to quarantine the target. These operations use the existing append contract, which gives no atomic transaction between sandbox effects and journal writes, and no recovery replay or tamper-resistance guarantee. [Gateway ordering](gateway-design.md#final-admission-and-execution)

## Bounded readback

The reader opens the trusted path read-only. Defaults are 16 KiB per line and 8 MiB per file, both measured in bytes including line terminators. These are trusted configurable limits. It recovers at the next line after malformed JSON, invalid UTF-8, duplicate keys, non-object data, non-finite numbers, schema violations or oversized records. A line cut short at EOF is reported as truncated even if its partial text forms a JSON value. A byte-limit or I/O failure stops the read while preserving prior observations. Diagnostics give line numbers and fixed codes. They omit input text, paths and exception messages. [Reader and issue codes](../src/agent_authz/audit/reader.py)

## Independent inventory and correlation

The Phase 7 pre-gateway observer captures each request, trusted binding and pre-attempt state. The runtime disposition identifies calls that actually proceeded through the gateway boundary, including forwarded malformed requests. Parser failures with no submission and unprocessed proposals stay outside the denominator. If the gateway fails before returning a correlation ID, the attempt remains in the independent denominator with missing correlation. The gateway result supplies final decision and versions, dispatch, execution, lifecycle, timing and failed-write indicators. The separate Phase 7 before-and-after observations supply verified effect and delivery evidence. The reader does not fill any of those independent fields.

The checker groups validated rows by request ID in file order. It counts duplicate row types and checks metadata, decisions and execution outcomes against the independent values. It allows increasing known record versions between checks and compares these with available before/after versions and the final returned decision. Wall-clock timestamps are checked for format and UTC. File order establishes sequence. Orphans are valid rows for IDs absent from the independent inventory. Uncorrelated rows have an ID claimed by multiple independent attempts. Invalid rows with no reliable association remain reader diagnostics. Duplicate inventory entries for one run and local sequence count once and receive a conflict.

| Observed path | Required sequence on a healthy journal |
| --- | --- |
| Structural rejection | `attempt → validation(false) → admission(denied)` |
| Preliminary policy denial | `attempt → validation(true) → preliminary(denied) → admission(denied)` |
| Later denial | `attempt → validation(true) → preliminary(allowed)`, then provisional intent if attempted, then denied admission |
| Actual dispatch | `attempt → validation(true) → preliminary(allowed) → dispatch_intent → admission(allowed) → dispatch → outcome`, then lifecycle where the trusted result reports one |
| Pre-dispatch write failure | Expected writes stop at the failed stage. The gateway also attempts to record denial. |
| No reliable terminal observation | Retain any journal prefix and report unknown terminal evidence. Intent alone establishes no dispatch or outcome. |

Each assessment retains its ordered records and all applicable issues. `inconsistent` takes precedence for conflicts, unexpected or duplicate events, and ordering errors. `incomplete` follows for missing correlation, missing required events and unconfirmed writes. `unknown` identifies missing independent observation when stronger issues are absent. A `complete` attempt has matched required events and independent evidence with no issues. Codes include `missing_correlation`, `missing_event`, `unconfirmed_write`, `missing_terminal_observation`, `duplicate_event`, `event_order`, and conflict codes for policy, binding, operation, validation, versions, decision, dispatch, execution, effect, lifecycle and timing. The checker never labels a request blocked solely from missing dispatch records.

The reusable fraction is complete attempts divided by all independently observed attempts. A zero denominator returns N/A. The report also counts each attempt status, invalid rows, orphan and uncorrelated lines, and issue codes. An otherwise complete attempt can coexist with journal-wide faults, which clear the global clean flag. This is a validation calculation. [Observations](../src/agent_authz/audit/observations.py) · [Completeness checker](../src/agent_authz/audit/completeness.py)

## Timing

Policy-decision time ends at validation rejection or the first policy verdict. Enforcement time includes the later checks and required persistence up to final admission or denial. Executor time starts at invocation and ends on return or exception. Per-event audit timings measure the write attempt through completion or failure. Trusted gateway overhead excludes executor time. It is measured separately from any adapter or inference time.

The journal provides available policy, enforcement and executor durations and histories of earlier writes. `GatewayResult.timing` supplies the complete write-duration sequence, including the last attempted write, and gateway overhead. The checker compares the journal's measurement values and write histories with that trusted result. Pre-dispatch audit time is already included in enforcement. The report keeps separate intervals without calculating aggregate latency statistics. [Timing definitions](experimental-design.md#latency-measurement-boundaries)

## Scenario integration and validation

`run_scenario(..., audit_path=path)` optionally creates an exclusive fresh journal, runs the normal case and returns its readback assessment in `ScenarioResult.audit`. An existing path is refused. With no path, the prior in-memory observation path remains available and returns no persistent audit assessment. `python -m agent_authz.audit.demo` uses a temporary directory and prints attempts, valid records, event names, status and numerator/denominator.

The tests cover all 36 normal case-policy-method combinations, malformed and legacy readback, correlation and event faults, late denial before and after intent, legitimate version changes, privacy sentinels and persistence failures. The reused gateway tests continue to cover denial without dispatch, binding, expiry, revocation and quarantine. Live Ollama inference remains unverified. The 42 X-case replay combinations remain unsupported, and no experimental ASR has been established. Phase 9 can consume the checker for supported runs and report evidence coverage before calculating any experimental metrics. [Scenario integration tests](../tests/test_audit_scenarios.py) · [Fault tests](../tests/test_audit_completeness.py) · [Scope](attack-scenarios.md#remaining-original-phase-7-acceptance-criteria)
