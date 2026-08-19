# LabMITM flow-inspector UI

React + TypeScript + Vite (Node **22.14.0**). The UI talks REST only (`/v1`).

Browser auth is `POST /v1/session` (bearer only — no HTTP Basic) → HttpOnly `labmitm_session` + CSRF in the JSON body / `GET /v1/session` reload recovery. Mutations send `X-LabMITM-CSRF`. The token is never written to `localStorage` or `sessionStorage`.

Pages: sign-in, flow list, flow detail (protocol badge, HTTP/2 stream id, headers / trailers / textual or hex body / TLS / download, SOCKS dest, original dest), status (including `ca.spkiSha256` and CA PEM download), scoped audit, gated reset. Live update uses `EventSource` `GET /v1/events/stream` with a 3s `GET /v1/flows` poll fallback.

Captured HTML is escaped text. There is no fuzzer, repeater, exploit, SSL-strip, Relay, or payload generator.

`web/go.mod` is a nested-module fence so parent `go test ./...` does not walk `node_modules`. Do not import `github.com/hilather/go-lab-mitmproxy/web` from the parent module. `//go:embed` cannot leave a module, so `make web-build` copies `web/dist` into `internal/web/dist`. The committed fallback is `internal/web/stub`.

```bash
npm --prefix web test
npm --prefix web run typecheck
npm --prefix web run build
```

Dev server proxies `/v1`, `/mcp`, and `/healthz` to `http://127.0.0.1:8088`.
