# Operator UI

Status: Implemented
Owners: Frontend, Control Plane
Last reviewed: 2026-10-04 (oct03 mock redesign: in-page confirms, plan review, tiles, local times)
Related ADRs: 0004, 0005, 0018, 0020, 0021

The embedded UI uses the authenticated native REST API. [ADR 0020](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0020-frontend-control-plane-parity.md) requires parity with all operator-facing REST/MCP capabilities. The capability registry remains 31 entries and the live mutation catalog remains eight verbs.

## Flows

The Flows workspace keeps its event stream mounted while the selection changes. List and selected-flow state refresh on insert, pause, resume, drop, delete and wipe; polling provides a fallback when SSE is unavailable. Server filters support host, method, status, scheme, rule ID, path prefix, protocol, transport (`via`) and intercepted status. All cursor pages are traversed. The local search box and the status chips (All / Paused / 2xx / 4xx / 5xx · error, with loaded counts) further narrow the loaded list without a request; 1xx, 3xx, tunnel and open rows appear only under All. Row status colour follows the same classification: 4xx amber, 5xx, errors, drops and breakpoint timeouts red, paused rows an accent chip.

Open **Filters & wait** in the list head; the popover ("Server filters and wait") keeps its values when closed, applied filters show as removable chips, and closing it never cancels a running wait. Opening the popover moves focus to the first filter field; Escape returns focus to the trigger. Rule ID suggestions come from the live state loaded at page start, after a Configuration apply or a Status refresh; rules changed through REST/MCP since then are not suggested until the next refresh, and free text is always accepted. Wait for a matching flow from the popover. Wait uses host, method, status, path prefix, protocol, transport, intercepted status and an optional RFC3339 `after` timestamp. Scheme and rule ID filter the list only. Timeout is a Go duration, such as `10s`. Cancel aborts the pending browser request. A match opens its inspector; timeout and other server errors remain visible — in the popover while it is open, otherwise in the list head — until the next wait or **Dismiss**.

The inspector shows protocol-specific detail in Request / Response / TLS (and Trailers, Frames, gRPC when present) tabs and the complete flow in a **Raw JSON** tab, rendered as text. Times are shown in browser-local time with the ISO value in the tooltip. Request and response bodies download as blob attachments so captured HTML cannot become a document navigation. Delete and Clear require an in-page confirmation ([ADR 0021](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0021-in-page-confirms-and-plan-review.md), D80), which holds the optional expected store generation input; the current generation is shown for reference. A stale precondition surfaces the server error without silently retrying.

Paused flows expose **Resume flow** and **Drop flow** to writers. Unchecked edits preserve the original headers/body. Checked empty edits explicitly clear them. Header rows preserve ordering and duplicates; copy captured headers to start an edit, or clear all rows. Drop terminates the paused exchange after an in-page confirm. **Replay flow** confirms one replay of the captured request through the existing guarded application operation, then displays the returned flow and a link to inspect it. Replay restrictions remain server-owned; the UI does not add arbitrary requests, scanning or bulk replay.

Request-phase Resume currently leaves the original breakpoint record `open` with status `0`; forwarding inserts the final completed capture under a new ID. Select that completed capture to inspect the response. Response-phase Resume completes the original record. The UI reports these existing store semantics without synthesizing a different result.

## Configuration and Status

Status shows health, CA identity, feature flags and convenient live editors. Its mutations first obtain the plan and show it in a **Review planned change** drawer (revisions, diff, warnings, raw JSON); **Apply reviewed changes** submits the same reviewed request and **Discard plan** sends nothing. Turning `ui.enabled` off asks for an in-page confirm with the D77 text.

Configuration is organised in tabs — **Live changes**, **Validate candidate**, **Export**, **Current state** — with errors and results shown above the tabs. Live changes has eight operation-template buttons, an Edit → Validate → Review plan → Apply stepper, and the plan-review panel. It exposes complete canonical state and a JSON operation editor with a current-state template and field guidance for every verb:

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

Disabling the UI and forcing store eviction require an additional in-page confirmation. YAML/JSON export shows the document, revision, bootstrap revision, drift and human diff. YAML revision headers are checked against metadata so a concurrent state change cannot mislabel the exported document.

Listener addresses and other Reset-only flags still require editing bootstrap outside the UI, then Reset. Reset confirms rereading bootstrap and wiping flows; the page shows a labelled snapshot (not live) of the flow count and store generation (from `GET /v1/status`), read at load, when the confirmation box is ticked, after a reset, and on **Refresh count**; Reset wipes whatever the store holds when it runs. The application never writes the bootstrap file. Startup-only adapter limitations, including changes to the public metrics route, still require a restart; see [known limitations](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/known-limitations.md).

## Diagnostics and Audit

Diagnostics shows Liveness, Readiness, Version (with build time), Protocols (from the same version read) and Metrics tiles, a filterable capabilities table (kind, idempotent, version) and the schema summary; each read refreshes on its own or with **Refresh all**, and raw responses stay one click away. Readiness failures retain their status body. Management metrics remain available only when `observability.metrics.publicPath: true` is set in bootstrap YAML; the route is fixed at process start, so changing it requires restarting labmitm (Reset does not change it). The schema can be downloaded from the running server.

Audit supports the native limit query and full event lookup by ID or list row, with Change (kv and diff table) and Raw event tabs. Capability chips (`changes.apply`, `flows.*`, …) and result chips (ok / not ok) filter the loaded events without a request. Times are browser-local. Blank/zero limits use the latest 100 events; the server caps results at 100. Switching events or identities discards stale detail responses. Audit requires `mitm.audit.read`; administrators satisfy all scopes. Configuration validation/export/plan/apply/reset require `mitm.admin`, flow writes require `mitm.write`, and normal reads require `mitm.read`.

## Parity maintenance

[web/parity.json](https://github.com/hilather/go-lab-mitmproxy/blob/main/web/parity.json) maps every registry entry and operation to a reachable workflow and named behavioral tests. Session capabilities map to login, session restoration and logout; events map to the live workspace. No native registry capability is exempted. Compatibility aliases reuse the native workflow.

`make test-parity` includes `make test-ui-parity`: the gate rejects missing/unknown capabilities and verbs, missing evidence, and unreviewed contract changes. Reviewed source digests include registry bindings/scopes, both adapters' DTOs/decoders, model fields and configuration schema because OpenAPI does not fully describe every input. Updating a digest is an explicit contract review, not proof of parity by itself: review changed fields and update the UI and its behavior tests before accepting it.

`make web-test` runs route reachability tests and requires every named evidence test to execute and pass. Skipped, missing, renamed or failed evidence fails the job. Gate regressions exercise these failure paths. `make web-build` checks types and bundles the embedded UI. Both the parity and web CI jobs are mandatory; semantic root and skeptic review complement these checks.
