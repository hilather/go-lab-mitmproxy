# LabMITM flow-inspector UI

React + TypeScript + Vite (Node **22.14.0**). The UI talks REST only (`/v1`).

Browser auth is `POST /v1/session` (bearer only — no HTTP Basic) → HttpOnly `labmitm_session` + CSRF in the JSON body / `GET /v1/session` reload recovery. Mutations send `X-LabMITM-CSRF`. The token is never written to `localStorage` or `sessionStorage`.

Pages: sign-in, Flows split-pane (list stays mounted; selection on `/` + `/flows/:id` drives Request / Response / TLS; intercept vs tunnel-not-decrypt chips; completed raw CONNECT is a tunnel summary), status (including `ca.spkiSha256` and CA PEM download), scoped audit, gated reset. Status / Audit / Reset / Login page bodies share the Flows dark lab chrome (IBM Plex; tunnel-not-decrypt stays a flow chip). Live update uses `EventSource` `GET /v1/events/stream` (`flow.inserted` / `flow.paused` / `flow.deleted` / `store.wiped`) with a 3s `GET /v1/flows` poll fallback. The header **:443 intercept only** chip and footer are overlay/default chrome copy, not live `tls.ports`.

Captured HTML is escaped text. There is no fuzzer, repeater, exploit, SSL-strip, Relay, or payload generator.

`web/go.mod` is a nested-module fence so parent `go test ./...` does not walk `node_modules`. Do not import `github.com/hilather/go-lab-mitmproxy/web` from the parent module. `//go:embed` cannot leave a module, so `make web-build` copies `web/dist` into `internal/web/dist`. The committed fallback is `internal/web/stub`.

```bash
npm --prefix web test
npm --prefix web run typecheck
npm --prefix web run build
```

Dev server proxies `/v1`, `/mcp`, and `/healthz` to `http://127.0.0.1:8088`.
