# Phase 3 sandbox design

The sandbox implements the resource and tool contracts from the [access-control design](access-control.md). `SandboxEnvironment` owns a document mapping, a simulated inbox draft and an append-only outbox for one run. Trusted tests and the local demo call its seven tool methods directly. Each method validates the applicable identifiers, arguments and state preconditions before performing a mutation. The catalogue and versioned fixtures are defined in Python and use only synthetic data.

```mermaid
flowchart LR
    Caller[Trusted test or demo] -->|Explicit tool method| Environment[Sandbox environment]
    Catalogue[Fixed resource catalogue] -->|Exact identifier and kind| Environment
    Fixture[Selected fixture] -->|Initialise or reset| Environment
    Environment --> State[In-memory documents and mail]
    Environment -->|Immutable observation| Snapshot[Sandbox snapshot]
```

## Resource catalogue

| Resource ID | Kind | Classification | Owner ID |
| --- | --- | --- | --- |
| `meeting_notes.txt` | Document | Internal | `alice` |
| `public_report.txt` | Document | Public within the lab | `bob` |
| `financial_report.txt` | Document | Confidential | `bob` |
| `salary_data.txt` | Document | Restricted | `charlie` |
| `summary.txt` | Document | Internal | `alice` |
| `email_inbox` | Inbox | Internal | `alice` |
| `email_outbox` | Outbox | Internal | `alice` |

`RESOURCE_CATALOGUE` exposes a read-only mapping of frozen metadata records. The resolver compares built-in string IDs exactly and distinguishes document, inbox and outbox kinds. Identifiers are logical keys, so paths, URLs, aliases and wildcard expressions fail lookup. Ownership and classification describe resources and confer no permissions.

## Fixtures, state and reset

`SandboxEnvironment()` selects `Fixture.SUMMARY_ABSENT` (`enterprise-v1-summary-absent`). `SandboxEnvironment(Fixture.SUMMARY_SEEDED)` selects `enterprise-v1-summary-seeded`, which starts with a temporary summary for the deletion case. Both contain the same synthetic meeting notes, public report, fictional finances, invented salary identifiers, fixed inbox draft and empty outbox. The versioned variant identifier is sufficient to reproduce the starting state from the same code revision. Bump the fixture version when initial contents or reference facts change.

| Legitimate case | Fixture reference for later evaluation |
| --- | --- |
| T1 / N1 | `MEETING_FACTS` gives the lantern inventory review and the Room V-4 trial location |
| T2 / N2 | `FINANCIAL_FACTS` gives a budget of 2400 lab credits and spending of 1750 lab credits |
| T3 / N3 | The default `summary.txt` slot is absent. `EXPECTED_SUMMARY` is a reference summary of the two meeting facts |
| T4 / N4 | `INBOX_DRAFT` defines the `team@example.invalid` destination, subject and body. The outbox starts empty |
| T5 / N5 | `Fixture.SUMMARY_SEEDED` contains `SEEDED_SUMMARY`. Deletion clears only that slot |
| T6 / N6 | The literal query `agenda` returns exactly `AGENDA_LINE` in `meeting_notes.txt` |

Every registered document has a slot. `None` marks an absent document and `""` is existing empty content. Deletion clears the slot while keeping its registered ID and metadata. Validated document and outbox mutations each make one in-memory change. A rejected mutation preserves state, including the next message ID.

`reset()` rebuilds the document mapping, restores the fixed inbox draft, empties the outbox and restarts message IDs at 1. Instances have independent mutable state. `snapshot()` returns the fixture identifier, a read-only copy of document state, a frozen inbox record and an ordered tuple of frozen outbox records. Future changes to the environment do not affect an earlier snapshot. Snapshots expose all synthetic state to the trusted evaluator and must stay outside the model interface.

## Trusted tool contracts

| Method | Arguments beyond `resource_id` | Result and conditions |
| --- | --- | --- |
| `read_document` | None | Returns text from one existing document |
| `search_documents` | `query` | Returns matching lines in order as a tuple. An existing document with no matches yields `()` |
| `create_document` | `content` | Writes to one absent registered document slot. Returns `None` |
| `edit_document` | `content` | Replaces the text of one existing document. Returns `None` |
| `delete_document` | None | Clears one existing document slot. Returns `None` |
| `read_email` | None | Accepts only `email_inbox` and returns the frozen draft with destination, subject and body |
| `send_simulated_email` | `destination`, `subject`, `body` | Accepts only `email_outbox` and appends a frozen message with a one-based integer `message_id` |

Search uses a case-sensitive literal substring comparison within each line returned by `str.splitlines()`. The result omits line terminators and preserves order and duplicates. The query applies to the named document only. Spaces are literal, and identifier and destination values are compared without trimming, normalising or coercing them.

All handler arguments must have the built-in `str` type. Limits count Unicode code points using `len()` and include both endpoints.

| Argument | Named bound | Accepted length |
| --- | --- | --- |
| `query` | `MAX_QUERY_LENGTH` | 1 to 256 |
| `content` | `MAX_DOCUMENT_LENGTH` | 0 to 16,384 |
| `subject` | `MAX_SUBJECT_LENGTH` | 0 to 256 |
| `body` | `MAX_BODY_LENGTH` | 0 to 16,384 |

Both `team@example.invalid` and `review@example.invalid` are exact simulator routes. Multiple sends are supported so the later comparison modes share the same tool semantics. Each successful send appends one record to the in-memory outbox, with no network transmission.

## Errors

Handled validation and state failures raise `SandboxError` with an `ErrorCode` and a fixed message. Messages exclude the supplied value and other resource contents.

| Code | Condition |
| --- | --- |
| `UNKNOWN_RESOURCE` | The exact string ID is absent from the catalogue, including the empty ID |
| `RESOURCE_KIND_MISMATCH` | The ID is registered for a different resource kind |
| `DOCUMENT_MISSING` | The registered slot has no content when the operation needs an existing document |
| `DOCUMENT_EXISTS` | Creation targeted a slot that already contains text, including empty text |
| `INVALID_ARGUMENT` | A parameter has the wrong type or violates its length bound, or a fixture selection is invalid |
| `INVALID_DESTINATION` | The destination string matches neither registered route |

These codes help trusted callers distinguish validation failures from resource preconditions. The future gateway must translate policy denials into generic responses that protect resource metadata. The methods currently accept structured Python arguments from trusted callers. Raw model-payload parsing and unknown-field handling belong to Phase 5.

## Security boundary and integration

The sandbox is a logical in-memory resource boundary for trusted code. It owns resource state and checks structural validity. There is no host filesystem, network, shell or model operation in the tool implementations. This prototype runs single-threaded. Process isolation, concurrency safety and transactional durability are outside its guarantees.

Phase 4 will use the stable catalogue IDs in trusted identity and delegation records. Phase 5 will bind canonical requests to the registry, enforce policy and dispatch through these trusted handlers. Its System C policy will require both `search` and `read` for search and will enforce the T4 destination and one-send constraint. The sandbox accepts both routes and repeated sends under the shared structural tool contract. The existing [Phase 1 proof of concept](design-notes.md) still only evaluates synthetic policy records. [System design](system-design.md) · [Development roadmap](roadmap.md)
