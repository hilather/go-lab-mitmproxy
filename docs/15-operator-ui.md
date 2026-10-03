# Operator UI

Status: Implemented
Owners: Frontend, Control Plane
Last reviewed: 2026-10-03 (field-violation display and conflict labels)
Related ADRs: 0004, 0005, 0018, 0020

The embedded UI uses the authenticated native REST API. [ADR 0020](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0020-frontend-control-plane-parity.md) requires parity with all operator-facing REST/MCP capabilities. The capability registry remains 31 entries and the live mutation catalog remains eight verbs.

## Flows

The Flows workspace keeps its event stream mounted while the selection changes. List and selected-flow state refresh on insert, pause, resume, drop, delete and wipe; polling provides a fallback when SSE is unavailable. Server filters support host, method, status, scheme, rule ID, path prefix, protocol, transport (`via`) and intercepted status. All cursor pages are traversed. The local search box further narrows the loaded list.

Expand **Server filters and wait** to wait for a matching flow. Wait uses host, method, status, path prefix, protocol, transport, intercepted status and an optional RFC3339 `after` timestamp. Scheme and rule ID filter the list only. Timeout is a Go duration, such as `10s`. Cancel aborts the pending browser request. A match opens its inspector; timeout and other server errors remain visible.

The inspector shows protocol-specific detail and an expandable complete JSON representation, rendered as text. Request and response bodies download as blob attachments so captured HTML cannot become a document navigation. Delete and Clear require confirmation and accept an optional expected store generation; the current generation is shown for reference. A stale precondition surfaces the server error without silently retrying.

Paused flows expose **Resume flow** and **Drop flow** to writers. Unchecked edits preserve the original headers/body. Checked empty edits explicitly clear them. Header rows preserve ordering and duplicates; copy captured headers to start an edit, or clear all rows. Drop terminates the paused exchange. **Replay flow** confirms one replay of the captured request through the existing guarded application operation, then displays the returned flow and a link to inspect it. Replay restrictions remain server-owned; the UI does not add arbitrary requests, scanning or bulk replay.

Request-phase Resume currently leaves the original breakpoint record `open` with status `0`; forwarding inserts the final completed capture under a new ID. Select that completed capture to inspect the response. Response-phase Resume completes the original record. The UI reports these existing store semantics without synthesizing a different result.

## Configuration and Status

Status shows health, CA identity, feature flags and convenient live editors. Its mutations first obtain and display the plan, then submit the same reviewed request after confirmation.

Configuration exposes complete canonical state and a JSON operation editor with a current-state template and field guidance for every verb:

| Verb | Editable subtree |
|---|---|
| `replaceStoreCaps` | maxFlows, maxBytes, maxBodyBytes, fullPolicy |
| `replaceAdmission` | session/in-flight/stream limits and timeouts |
| `replaceTLS` | intercept, hosts, ports, CA file references, upstream verification and extra CA files |
| `replaceRules` | enabled and complete rule items |
| `replaceTargets` | target guard booleans and host allow/deny lists |
| `replaceCompat` | flowREST enabled and pathPrefix |
| `setFeature` | existing live feature ID and enabled |
| `replaceHTTPAuth` | enabled, realm and credential-file references |

Edit the selected operation or add several operations to its array for one atomic change. Byte sizes use IEC strings; durations use Go duration strings. Replacement subtrees follow the same defaults and validation as REST/MCP. File references remain references; the browser never reads private keys or credential files.

**Validate operations**, **Validate candidate state**, and **Validate candidate with operations** are separate read-only checks. Candidate JSON can include bootstrap-only settings, but validation does not apply or save it. **Plan changes** displays the exact request, diff and warnings. **Apply reviewed changes** submits that same revision, idempotency key, reason, force and payload. Editing any reviewed input invalidates the plan. Automatically generated keys change for new drafts; a network failure retains the exact request for an idempotent retry. Any `409` refreshes state and requires another explicit plan; the message follows the error code: `revision_conflict` reports a runtime revision change, `idempotency_conflict` reports a key reused for a different request, and other conflicts name their code. Error messages outside sign-in include field violations (`path: message [code]`) and remediation when the server returns them. User-supplied keys remain deliberate overrides and must not be reused for a different payload.

Disabling the UI and forcing store eviction require additional confirmation. YAML/JSON export shows the document, revision, bootstrap revision, drift and human diff. YAML revision headers are checked against metadata so a concurrent state change cannot mislabel the exported document.

Listener addresses and other Reset-only flags still require editing bootstrap outside the UI, then Reset. Reset confirms rereading bootstrap and wiping flows. The application never writes the bootstrap file. Startup-only adapter limitations, including changes to the public metrics route, still require a restart; see [known limitations](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/known-limitations.md).

## Diagnostics and Audit

Diagnostics reads and refreshes version, capabilities, configuration schema, liveness, readiness and metrics. Readiness failures retain their status body. Management metrics remain available only when `observability.metrics.publicPath` is configured. The schema can be downloaded from the running server.

Audit supports the native limit query and full event lookup by ID or table row, including diffs. Blank/zero limits use the latest 100 events; the server caps results at 100. Switching events or identities discards stale detail responses. Audit requires `mitm.audit.read`; administrators satisfy all scopes. Configuration validation/export/plan/apply/reset require `mitm.admin`, flow writes require `mitm.write`, and normal reads require `mitm.read`.

## Parity maintenance

[web/parity.json](https://github.com/hilather/go-lab-mitmproxy/blob/main/web/parity.json) maps every registry entry and operation to a reachable workflow and named behavioral tests. Session capabilities map to login, session restoration and logout; events map to the live workspace. No native registry capability is exempted. Compatibility aliases reuse the native workflow.

`make test-parity` includes `make test-ui-parity`: the gate rejects missing/unknown capabilities and verbs, missing evidence, and unreviewed contract changes. Reviewed source digests include registry bindings/scopes, both adapters' DTOs/decoders, model fields and configuration schema because OpenAPI does not fully describe every input. Updating a digest is an explicit contract review, not proof of parity by itself: review changed fields and update the UI and its behavior tests before accepting it.

`make web-test` runs route reachability tests and requires every named evidence test to execute and pass. Skipped, missing, renamed or failed evidence fails the job. Gate regressions exercise these failure paths. `make web-build` checks types and bundles the embedded UI. Both the parity and web CI jobs are mandatory; semantic root and skeptic review complement these checks.
