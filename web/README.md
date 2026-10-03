# LabMITM flow-inspector UI

Last reviewed: 2026-10-03 (implemented operator workflows and mandatory parity gate)

React + TypeScript + Vite (Node **22.14.0**). The UI talks REST only (`/v1`).

Browser auth is `POST /v1/session` (bearer only — no HTTP Basic) → HttpOnly `labmitm_session` + CSRF in the JSON body / `GET /v1/session` reload recovery. Mutations send `X-LabMITM-CSRF`. The token is never written to `localStorage` or `sessionStorage`.

The Flows workspace (`/` and `/flows/:id`) keeps the list mounted while selecting an inspector. Server filters and complete cursor traversal load matching flows; local search narrows the loaded list. A cancellable wait opens its matching flow. Writers can resume paused exchanges with ordered header/body edits, explicitly clear those fields, drop a paused flow, or confirm one guarded replay of a captured flow. Delete and Clear accept optional store-generation preconditions and require confirmation. Protocol detail includes Request / Response / TLS, Trailers / Frames / gRPC when present, and complete escaped JSON. Raw CONNECT captures show a tunnel summary; handshake failures remain errors.

Status shows readiness, CA identity/SPKI and PEM download, the feature catalog and compact Reset-required flags. Its convenient live editors first obtain a plan and apply the exact reviewed changeset after confirmation; `ui.enabled` off needs additional confirmation. Configuration (`/configuration`) exposes all eight live verbs with complete subtree fields, including TLS hosts/ports/CA references/upstream settings, store caps, targets, admission, rules, compat, live feature IDs and HTTP proxy authentication. It validates operations, complete candidate state, or both; reviews an immutable plan before apply; accepts reason/force/idempotency settings; and exports canonical YAML/JSON with revision, drift and diff metadata. Listener addresses and Reset-only flags still require external bootstrap edits and gated Reset. The UI never writes bootstrap.

Diagnostics (`/diagnostics`) reads and refreshes version, capabilities, running configuration schema, liveness, readiness and configured management metrics. Scoped Audit supports the native limit and full event lookup by ID or row, including diffs. Sign-in, Status, Configuration, Diagnostics, Audit and Reset share the Flows dark lab chrome (IBM Plex). See the [operator UI guide](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/15-operator-ui.md) for scopes, confirmations and mutation semantics.

Live update uses `EventSource` `GET /v1/events/stream` (`flow.inserted`, `flow.paused`, `flow.resumed`, `flow.dropped`, `flow.deleted`, `store.wiped`), refreshing the list and selected flow, with a 3s `GET /v1/flows` poll fallback. The header intercept chip reads live `GET /v1/state` `canonical.spec.tls.ports`. CONNECT footer / `TUNNEL_REASON` stay overlay `tls.ports:[443]`.

Captured HTML is escaped text; body downloads use blob attachments. Fuzzer, repeater, bulk attack automation, exploit, SSL-strip, Relay, and payload-generator tooling remain excluded. [ADR 0020](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0020-frontend-control-plane-parity.md) includes the implemented single operator-requested replay of a captured flow through the existing guarded `flows.replay` capability.

UI-PARITY-001 implements the workflows and mandatory parity gate. `make test-parity` includes `make test-ui-parity`, which checks the registry, all eight verbs and reviewed API contracts against [web/parity.json](https://github.com/hilather/go-lab-mitmproxy/blob/main/web/parity.json). `make web-test` requires every mapped behavioral test to execute and pass; `make web-build` checks types and produces the embedded bundle. These checks are mandatory.

```bash
make test-ui-parity
make test-parity
make web-test
make web-build
```

`web/go.mod` is a nested-module fence so parent `go test ./...` does not walk `node_modules`. Do not import `github.com/hilather/go-lab-mitmproxy/web` from the parent module. `//go:embed` cannot leave a module, so `make web-build` copies `web/dist` into `internal/web/dist`. The committed fallback is `internal/web/stub`.

```bash
npm --prefix web test
npm --prefix web run typecheck
npm --prefix web run build
```

Dev server proxies `/v1`, `/mcp`, and `/healthz` to `http://127.0.0.1:8088`.
