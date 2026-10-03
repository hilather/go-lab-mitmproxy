# LabMITM flow-inspector UI

Last reviewed: 2026-10-03 (frontend parity policy and implementation boundary)

React + TypeScript + Vite (Node **22.14.0**). The UI talks REST only (`/v1`).

Browser auth is `POST /v1/session` (bearer only — no HTTP Basic) → HttpOnly `labmitm_session` + CSRF in the JSON body / `GET /v1/session` reload recovery. Mutations send `X-LabMITM-CSRF`. The token is never written to `localStorage` or `sessionStorage`.

Pages: sign-in, Flows split-pane (list stays mounted; selection on `/` + `/flows/:id` drives Request / Response / TLS; intercept vs tunnel-not-decrypt chips; completed raw CONNECT is a tunnel summary; Frames tab badges `drop`/`block`), status (including `ca.spkiSha256` and CA PEM download; live `replaceTLS` / `replaceHTTPAuth` / `replaceRules` / `replaceAdmission` / `replaceCompat`; compact `httpAuth` + Reset-required 1.2 flags; gated `ui.enabled` off-confirm), scoped audit, gated reset. Status / Audit / Reset / Login page bodies share the Flows dark lab chrome (IBM Plex; tunnel-not-decrypt stays a flow chip). Live update uses `EventSource` `GET /v1/events/stream` (`flow.inserted` / `flow.paused` / `flow.deleted` / `store.wiped`) with a 3s `GET /v1/flows` poll fallback. The header intercept chip reads live `GET /v1/state` `canonical.spec.tls.ports`. CONNECT footer / `TUNNEL_REASON` stay overlay `tls.ports:[443]`.

Captured HTML is escaped text. Fuzzer, repeater, bulk attack automation, exploit, SSL-strip, Relay, and payload-generator tooling remain excluded. [ADR 0020](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0020-frontend-control-plane-parity.md) permits the existing guarded `flows.replay` operation as a single operator-requested replay of a captured flow. UI-PARITY-001 will add that browser workflow, the remaining operator capabilities, and the mandatory automated frontend parity gate. The pages described above are the current baseline; this policy change adds no browser implementation or gate. Existing REST/MCP parity and web test/build checks remain required.

`web/go.mod` is a nested-module fence so parent `go test ./...` does not walk `node_modules`. Do not import `github.com/hilather/go-lab-mitmproxy/web` from the parent module. `//go:embed` cannot leave a module, so `make web-build` copies `web/dist` into `internal/web/dist`. The committed fallback is `internal/web/stub`.

```bash
npm --prefix web test
npm --prefix web run typecheck
npm --prefix web run build
```

Dev server proxies `/v1`, `/mcp`, and `/healthz` to `http://127.0.0.1:8088`.
