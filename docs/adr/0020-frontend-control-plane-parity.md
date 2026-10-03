# ADR 0020: Frontend control-plane parity

Status: Accepted
Date: 2026-10-03
Last reviewed: 2026-10-03 (supported inputs and delivered UI-PARITY-001)
Decisions: D79

## Context

REST and MCP expose the shared capability registry, but the embedded inspector has exposed only a subset. Operators can configure breakpoint rules without being able to resume the paused flows, and several configuration and inspection workflows require leaving the UI. REST/MCP parity tests alone do not detect these omissions.

## Decision

**D79 — The frontend must provide functional parity with every operator-facing REST/MCP capability.** The browser remains a REST client; domain behavior and authorization remain in the shared application layer. Existing routes, capability IDs, mutation semantics, and bootstrap ownership do not change.

Parity includes supported inputs and results, filtering and pagination, optional fields and explicit empty edits, validation and errors, scope restrictions, concurrency preconditions, idempotency and reasons where the native capability supports them, and confirmation of destructive actions. A hidden API helper or a declaration in a coverage table is not a usable operator workflow. Settings workflows must expose all eight existing apply verbs, their editable fields, candidate validation, plan review, and canonical export. Reset-only settings remain bootstrap plus Reset; the UI must explain this boundary and must never write the bootstrap file. Configuration plan review retains the exact existing changeset through apply; there is no plan ID or new apply protocol. Per operation: configuration plan and apply take an expected revision, idempotency key, reason, and force flag; candidate validation uses only the candidate state and operations; Reset takes only a reason; flow delete and clear take an expected store generation; resume takes only replacement headers and body (REST rejects `reason` there as `unknown fields`); drop and replay have no inputs beyond the flow ID. Do not invent unsupported idempotency or reason fields for other capabilities.

Captured-flow replay is the existing guarded `flows.replay` operation. A single operator-requested replay is permitted in the UI. This does not introduce scanning, fuzzing, bulk attack automation, or arbitrary requests unrelated to a captured flow. The previous UI omission of replay is superseded to this extent only.

Every central registry capability must have an explicit frontend disposition. Operator capabilities map to reachable UI workflows and behavioral regression coverage. Transport-only entries may map to the existing session, live-update, or download machinery, or to a documented protocol-only exemption. Compatibility aliases do not require duplicate screens. Exemptions must identify the actual protocol reason and cannot conceal an unimplemented operator capability.

UI-PARITY-001 introduces a mandatory automated frontend parity check that compares the registry and operation schema against frontend coverage, failing for new or unclassified capabilities, missing operations, invalid routes, and missing behavioral evidence. UI behavioral tests verify the calls and outcomes. Once it lands, run this check alongside REST/MCP parity and the frontend test/build jobs; `make test-parity` checks REST and MCP only, not the UI. New API capabilities and inputs must update their UI and tests in the same change.

## Implementation rollout

The policy was adopted separately from its implementation. UI-PARITY-001 now delivers the required browser workflows and mandatory automated frontend parity gate. Existing REST/MCP parity and web test/build checks remain mandatory alongside that gate; the delivered controls are documented in the [operator UI guide](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/15-operator-ui.md).

## Consequences

- The embedded UI is an operator control plane as well as a flow inspector.
- Flow resume/edit/drop/replay/wait, state validation/export/planning, full live settings, and diagnostic reads are included in frontend scope.
- Existing REST/MCP errors and security boundaries remain authoritative. No browser-side business logic replaces server validation.
- UI inputs and test coverage evolve with API contracts. Generic raw JSON output may supplement useful controls but is not a substitute for usable flow and mutation workflows.
- UI-PARITY-001 closes the identified workflow gaps and introduces the mandatory parity gate.

## Alternatives considered

- Continue testing REST/MCP parity only: rejected because a green API check leaves operator workflows inaccessible.
- Require duplicate screens for protocol bindings: rejected; parity concerns operator functionality rather than transport mechanics.
- Add a separate browser API or write bootstrap YAML from the UI: rejected; shared capabilities and GitOps ownership stand.

## Review triggers

Review when a public capability or input cannot be represented safely in the UI, or a protocol-only exemption is requested. Architectural exceptions require an ADR rather than an untested coverage declaration.
