# Known limitations (1.0)

LabMITM is a laboratory intercepting proxy, not a public edge proxy and not an attack framework. Residuals below are closed 1.0 decisions, not accidental gaps.

- HTTP/1.1 only. Clients that require HTTP/2 to the origin will fail ALPN (they should fall back; some do not).
- No SOCKS, TPROXY, reverse-proxy, or transparent intercept.
- No WebSocket **frame** inspect (101 + bidirectional copy only).
- No mitmproxy addon / mitmweb / Python addon compatibility.
- Generate-mode CA rotates on every restart/reset. Operators who need a stable CA use `tls.ca.mode: files`.
- Store-full still forwards (capture is best-effort when the inspector is full).
- Single replica; no shared flow store.
- MCP clients requiring OAuth PRM cannot authorize. MCPJungle needs `allowLegacyClients: true` (family-doc reason; image SDK version not re-measured here).
- Proxy data plane is unauthenticated; publishing `:8888` on a LAN is an operator choice with documented risk.
- No Proxy-Authorization in 1.0.
- HTML preview of captured pages is escaped text (optional sandboxed iframe is off by default).
- Intercept **breaks origin mTLS and certificate pinning**.
- Default metadata CIDRs are AWS/GCP IPv4 + AWS IPv6 IMDS. Alibaba `100.100.100.200/32` and RFC1918 are **not** default-deny (lab SUTs).
- Not a general attack tool. No fuzzer, payload generator, SSL-strip, or exploit UX.
- TLS-001 intercepts HTTPS on listed ports (`ports` default `[443]`) with an in-process lab CA. STORE-001 captures completed flows in a process-local Memory inbox (wipe on shutdown/reset). RULES-001 evaluates first-match rewrite/breakpoint from YAML (`rules.enabled` default-off). STA-001 compiles YAML into a snapshot. API-001 serves native REST `/v1` (problem+json, HMAC cursors, wait/resume/drop/replay, cert-only `GET /v1/ca`). Session cookie/CSRF is SEC-001; the production SPA is UI-001; MCP is MCP-001. The image is not shipped yet.

See [docs/01-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/01-architecture.md#residual-limitations-10) for the architecture-pack copy of these residuals.
