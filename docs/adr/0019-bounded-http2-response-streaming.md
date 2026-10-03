# ADR 0019: Bounded HTTP/2 response streaming

Status: Accepted
Date: 2026-10-02
Decisions: D78 (D37 oversized-response exception)

## Context

The HTTP/2 response adapters previously read the entire origin body into memory before forwarding it. This bypassed the capture limit, delayed streaming responses until EOF, and retained a second full copy during capture. Capture-only traffic must instead forward headers and body incrementally under the existing capture caps.

[ADR 0009](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0009-http2-via-http2x.md) D44 reserves a single HTTP/1.1 origin connection through the complete response body. The D37 breakpoint rule in [proxy semantics](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md) requires response pauses outside that reservation. For an oversized response these guarantees cannot both hold: retaining the unread body while releasing the connection requires unbounded buffering or additional persistence.

## Decision

**D78 — Stream HTTP/2 responses with bounded capture.** Both intercepted HTTP/2 and client-facing h2c send response headers and forward body bytes without waiting for origin EOF on the capture-only path. Capture retains at most `store.maxBodyBytes` per body. Existing mutating rules retain only a capped prefix and stream the remaining body when the cap is exceeded.

For HTTP/2 transcoded onto an HTTP/1.1 origin, the D44 mutex remains held until the original response body is consumed or closed. A response breakpoint whose body fits in the capture cap releases the origin connection before `WaitPaused`, preserving D37. **An oversized response breakpoint retains that reservation while paused and while forwarding the unread tail.** Other streams can run request-phase rules but wait to use that origin connection. Resume, Drop, timeout, cancellation, and connection shutdown must release the reservation as appropriate.

This is a narrow exception to D37 for oversized HTTP/1.1-origin response breakpoints. Request breakpoints still run before taking the origin mutex. HTTP/2 origins continue multiplexing independently. There is no second origin dial, body spool, new persistence, schema field, capability, or apply verb. D7, D19, D20, D21, D27, D44, and the existing capture limits stand.

## Consequences

- SSE and other long-lived responses can deliver headers and data before EOF; captured flows are finalized when forwarding ends.
- Large responses no longer require memory proportional to their full length.
- An operator pausing an oversized response on a shared HTTP/1.1 origin can delay other streams on that connection until the pause and unread body finish. Existing breakpoint and upstream timeouts still apply.
- An explicit bounded Resume body replaces the whole response, including an oversized original. Its unread origin body is closed. If that closes the shared HTTP/1.1 origin TCP, later streams on the same CONNECT cannot redial; the client must establish a new CONNECT. Nil or header-only Resume preserves and forwards the original tail.
- Regression coverage must include incremental delivery, truncation, trailers, cancellation, small-response breakpoint independence, and oversized-response reservation release.

## Alternatives considered

- Buffer every response completely: rejected because it defeats resource limits and streaming.
- Spool response bodies: rejected because it adds persistence outside the current architecture.
- Open another origin connection: rejected by D27.
- Discard the unread tail or silently skip the breakpoint: rejected because it changes the requested response or rule behavior.

## Review triggers

Review when persistent response spooling, multiple origin connections per CONNECT, or a different oversized-breakpoint policy is proposed.
