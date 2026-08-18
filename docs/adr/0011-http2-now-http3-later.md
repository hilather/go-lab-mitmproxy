# ADR 0011: HTTP/2 in 1.0; HTTP/3 in 1.1

Status: Accepted
Date: 2026-08-18
Decisions: D9

## Context

mitmproxy enables HTTP/2 and HTTP/3 by default. HTTP/3 requires QUIC (likely `quic-go`) and UDP listeners, which expands the security and container surface.

## Decision

HTTP/2 is 1.0 (H2-001) via `golang.org/x/net/http2`. HTTP/3 and raw QUIC are H3-001 / 1.1. Schema `http3: true` fails validate in 1.0. Reverse `http3://` and `quic://` fail validate.

## Consequences

- `Alt-Svc` stripped by default in reverse mode so clients do not bypass to HTTP/3.
- Parity with mitmproxy HTTP/3 is scheduled.

## Alternatives considered

- HTTP/3 in 1.0: too much concurrent risk with the proxy core; deferred.
