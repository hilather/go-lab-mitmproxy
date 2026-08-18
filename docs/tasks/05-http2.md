# H2-001: HTTP/2

Status: not-started
Recommended owner: HTTP/2 agent
Dependencies: TLS-001
Exclusive ownership: `internal/proxy/h2`
Wave: 4 (parallel with WS-001, MODE-001, ADDON-001)

## Goal

Intercept HTTP/2 on TLS ALPN `h2`; translate to HTTP/1.1 upstream when needed.

## Design references

- [ ] `docs/02-proxy-semantics.md` HTTP/2
- [ ] ADR 0011
- [ ] `docs/01-architecture.md` allowed deps (`x/net`)

## Scope

- [ ] Adapter wrapping `golang.org/x/net/http2`; types do not leak.
- [ ] ALPN offer `h2`, `http/1.1`.
- [ ] Header lowercasing / `normalizeOutboundHeaders`.
- [ ] Ping keepalive.
- [ ] Flows recorded as HTTP with `HTTPVersion: h2`.

## Explicit non-scope

- HTTP/3 (H3-001).

## Required tests

- [ ] **Integration:** curl `--http2 -x --cacert` to h2 origin.
- [ ] Translation to H1 origin.
- [ ] `http2: false` negotiates HTTP/1.1 only.

## Acceptance criteria

- H2 intercept round-trip in CI without external network.
