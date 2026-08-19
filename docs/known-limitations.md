# Known limitations (1.0 / v1.0.0-rc.1)

Honest residual for LabMITM 1.0, last reviewed against this tree’s **v1.0.0-rc.1** notes. These are not defects hidden from the notes. They are out-of-scope product bounds or work that is **not** claimed here.

Last reviewed: 2026-08-18 (GA-001 + SWAP-001)

This file is the operator-facing residual list. The numbered pack still wins on conflict: [docs/01-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/01-architecture.md#residual-limitations-10). Release notes: [docs/releases/v1.0.0-rc.1.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/releases/v1.0.0-rc.1.md).

LabMITM is a **laboratory intercepting proxy**. It is **not a public** edge proxy and not an attack framework.

## This tree versus what is not tagged

Design PRs 1–14, the flow-inspector SPA, hardened image files, and SWAP overlay examples are in this tree. What is **not** this candidate:

| In this tree | Not this tag |
|---|---|
| PROXY/TLS/STORE/RULES/STA/API/MCP/SEC/OBS/DEP files, SWAP examples, flow-inspector SPA, GA notes | Published `ghcr.io/hilather/labmitm` digest |
| First-party flow-inspector SPA | mitmproxy mitmweb / Python addon UI |
| Overlay examples in this repo | mcp-integration-lab compose/image pin |

**GA / 1.0 is not this rc.** The flow-inspector UI is present (D13). That does not make this SHA a 1.0 GA tag. 1.0 ships the appliance; lab compose-in is a follow-on (D18). Do not claim the lab already runs LabMITM.

## Not a public edge proxy

- HTTP/1.1 only. Clients that require HTTP/2 to the origin will fail ALPN (they should fall back; some do not).
- No SOCKS, TPROXY, reverse-proxy, or transparent intercept.
- No WebSocket **frame** inspect (101 + bidirectional copy only).
- No mitmproxy addon / mitmweb / Python addon compatibility.
- No Proxy-Authorization in 1.0. The proxy data plane is unauthenticated; publishing `:8888` on a LAN is an operator choice with documented risk.
- Intercept **breaks origin mTLS and certificate pinning**.
- Not a general attack tool. No fuzzer, payload generator, SSL-strip, or exploit UX.

## Proxy and TLS (this tree)

- Default standalone binds stay loopback `127.0.0.1:8888` / `127.0.0.1:8088` (D10). The lab overlay is the place that publishes `:8888`/`:8088`.
- Generate-mode CA rotates on every restart/reset. Operators who need a stable CA use `tls.ca.mode: files`.
- Default metadata CIDRs are AWS/GCP IPv4 + AWS IPv6 IMDS. Alibaba `100.100.100.200/32` and RFC1918 are **not** default-deny (lab SUTs).
- HTML preview of captured pages is escaped text (optional sandboxed iframe is off by default).

## Store

- Store-full still forwards (capture is best-effort when the inspector is full).
- Single replica; no shared flow store.
- MCP clients requiring OAuth PRM cannot authorize. MCPJungle needs `allowLegacyClients: true` (family-doc reason; image SDK version not re-measured here).
- Proxy data plane is unauthenticated; publishing `:8888` on a LAN is an operator choice with documented risk.
- No Proxy-Authorization in 1.0.
- HTML preview of captured pages is escaped text (optional sandboxed iframe is off by default).
- Intercept **breaks origin mTLS and certificate pinning**.
- Default metadata CIDRs are AWS/GCP IPv4 + AWS IPv6 IMDS. Alibaba `100.100.100.200/32` and RFC1918 are **not** default-deny (lab SUTs).
- Not a general attack tool. No fuzzer, payload generator, SSL-strip, or exploit UX.
- TLS-001 intercepts HTTPS on listed ports (`ports` default `[443]`) with an in-process lab CA. STORE-001 captures completed flows in a process-local Memory inbox (wipe on shutdown/reset). RULES-001 evaluates first-match rewrite/breakpoint from YAML (`rules.enabled` default-off). STA-001 compiles YAML into a snapshot. API-001 serves native REST `/v1` (problem+json, HMAC cursors, wait/resume/drop/replay, cert-only `GET /v1/ca`). MCP-001 serves Streamable HTTP `POST /mcp` (`mitm_*` tools, `labmitm://` resources, URI-only listen) and `labmitm mcp-stdio --token-file`. SEC-001 is lab static bearer (no Basic), REST cookie `labmitm_session` + CSRF, origin allowlist; unauthenticated `GET /v1/flows` is 401. DEP-001 ships the hardened scratch image (`USER 65532:65532`, system CA bundle, compose smoke). The production SPA is UI-001.
- TLS-001 intercepts HTTPS on listed ports (`ports` default `[443]`) with an in-process lab CA. STORE-001 captures completed flows in a process-local Memory inbox (wipe on shutdown/reset). RULES-001 evaluates first-match rewrite/breakpoint from YAML (`rules.enabled` default-off). STA-001 compiles YAML into a snapshot. API-001 serves native REST `/v1` (problem+json, HMAC cursors, wait/resume/drop/replay, cert-only `GET /v1/ca`). MCP-001 serves Streamable HTTP `POST /mcp` (`mitm_*` tools, `labmitm://` resources, URI-only listen) and `labmitm mcp-stdio --token-file`. SEC-001 is lab static bearer (no Basic), REST cookie `labmitm_session` + CSRF, origin allowlist; unauthenticated `GET /v1/flows` is 401. UI-001 embeds the React flow-inspector at `/` (REST only; `spec.ui.enabled: false` 404s `/`). The image is not shipped yet.

## Control plane

- MCP clients requiring OAuth PRM cannot authorize. MCPJungle needs `allowLegacyClients: true` (family-doc reason; image SDK version not re-measured here).
- MCP protocol is **2026-07-28**. `mcp-stdio` is a developer adapter, not an image entrypoint.
- Management is bearer-only (D6). There is no HTTP Basic.
- Catalog id is **`labmitm`**. There is no predecessor mitmproxy service to preserve.

## Deployment

- Healthcheck plane is HTTP `/v1/health/ready`. Ready still requires the proxy listener bound.
- Dockerfile and `make test-container` are in-tree. This candidate does not publish a `ghcr.io/hilather/labmitm` digest, SBOM, or provenance.
- Application binaries built without ldflags report version `dev`. The notes version `1.0.0-rc.1` is the candidate identity for the tag, not the default `dev` string.
- Required GitHub Actions green-on-tag is enforced by Release `tag-gate`.
- Overlay examples live in this repo. Compose/image pin in mcp-integration-lab is a follow-on (D18).

## Explicit non-goals (unchanged)

Reverse-proxy / TPROXY / SOCKS, HTTP/2 or HTTP/3, WebSocket frame inspect, mitmproxy addon / mitmweb / Python VM, wrapping the Python mitmproxy binary, public / well-known CA, exploit generation, SSL-strip, LabDNS-style random chaos, durable flow-directory, multi-replica store, HTTP Basic, OAuth PRM, and claiming the lab already runs LabMITM.
