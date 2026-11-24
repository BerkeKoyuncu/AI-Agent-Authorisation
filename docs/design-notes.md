# Phase 1 — Initial design decisions

- Use Python standard-library dataclasses and immutable permission sets.
- Model permission as an exact (action, resource_id) pair rather than independent lists, to avoid granting unintended combinations.
- Keep the untrusted request separate from trusted execution context.
- Resolve synthetic identity and task records from trusted in-memory mappings; these are fixtures, not authentication credentials.
- Deny by default when an explicit permission is missing.
- The phase-one policy only evaluates exact resource IDs and READ/CREATE actions. It is not a full gateway, does not execute tools, and does not enforce a process isolation boundary.
- Future work: threat model, sandbox tools, canonical request validation, real execution boundary, richer contextual policies, baseline modes, audit logging, model integration and evaluation.
- The policy's unit tests verify selected expected decisions; they do not establish resistance to prompt injection in a real agent.
