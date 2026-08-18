# ADR 0002: In-tree proxy core

Status: Accepted
Date: 2026-08-18
Decisions: D7, D8

## Context

Family appliances own protocol state machines. Exec’ing `mitmdump` or vendoring a full Python stack cannot provide a capability registry or scratch image. Third-party Go proxy frameworks center different APIs than REST/MCP parity and intercept-hold.

## Decision

**D7 — In-tree proxy core** in `internal/proxy/{codec,server,h2,ws}`. HTTP/2 uses `golang.org/x/net/http2` behind an adapter. No `elazarl/goproxy`, `google/martian`, or Python child process.

**D8 — 1.0 modes:** `regular`, `reverse`, `socks5`, `upstream`.

## Consequences

- CONNECT, intercept-hold, and replay are first-class.
- More session code than wrapping a library.
- Interop tests against curl and `net/http` are mandatory.

## Alternatives considered

- Wrap mitmproxy: rejected ADR 0010.
- goproxy: intercept/replay/H2/MCP mismatch.

## Review triggers

If PROXY-001+H2-001 cannot reach documented interop by M2, a narrowly scoped library behind `internal/proxy` requires a new ADR — not a product-level Python wrap.
