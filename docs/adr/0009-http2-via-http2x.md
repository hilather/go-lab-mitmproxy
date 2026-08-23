# ADR 0009: HTTP/2 via http2x (D8 scope)

Status: Accepted
Date: 2026-08-19
Decisions: D26, D27, D28, D32, D44, D45, D46, D47, D48, D53

## Context

ADR 0002 **D8** required HTTP/1.1 on every hop in 1.0. Browsers and gRPC SUTs negotiate ALPN `h2`; 1.0 closes the intercepted session (`Error=http2_inner`). Intercepting HTTP/2 needs a frame codec the family does not own in-tree.

This ADR supersedes ADR 0002 **D8 scope only**. **D7, D16, D19, D20, and D21 stand.** The proxy stays in-tree. Third-party MITM/proxy libraries stay forbidden. CONNECT still Hijacks. Dial isolation is unchanged. Handshake failure still does not blind-tunnel. Origin fetches still use `Transport.RoundTrip` only.

## Decision

**D26 — HTTP/2 is inner + origin only.** The client-facing cleartext proxy hop stays HTTP/1.1. `PRI * HTTP/2.0` is a hard close on every data-plane listener.

**D27 — D19 preserved.** One CONNECT / SOCKS CONNECT / orig-dest TCP = one upstream TCP (and at most one upstream TLS). One captured flow per request stream.

**D28 — `golang.org/x/net/http2` behind `internal/http2x`.** Codec, not a proxy library. No Dial idents. A `DialTLS` field stays nil. Added as a direct module in the codec PR (BSD-3, Apache-2.0 compatible).

**D32 — ALPN preference + transcode, not lockstep.** Client handshake first. Origin may pick the other proto. Handshake failure still does not blind-tunnel (D20). This tree transcodes h2 inner onto HTTP/1.1 origin (`NextProtos` stay `http/1.1`).

**D44 — h2 client + h1 origin serializes streams** on the single origin TCP: mutex covers `RoundTrip` and full body drain; `MaxConnsPerHost: 1`.

**D45 — `http2x` is not a bare `http.Handler`.** Per-stream values carry StreamID, ordered pseudos, headers, trailers, and body.

**D46 — Handshake NextProtos come from the session snapshot**, not from Authority compile.

**D47 — Captured `Protocol` is the inner client protocol.**

**D48 — Inner hop rejects CONNECT and Extended CONNECT** (`:method=CONNECT` or `:protocol`).

**D53 — `roundTripInnerH2` must not write HTTP/1.1 to the client TLS conn** and must not close the CONNECT on a per-stream origin error.

`protocols.http2.enabled` defaults false. Handshake NextProtos are taken from the session snapshot (D46). Inner HTTP/2 capture is not wired in the codec PR; inner `PRI` still records `http2_inner`.

## Consequences

- 1.0 transcripts stay green while the flag is off.
- `golang.org/x/net/http2` is a codec behind `internal/http2x` only.
- D7 is **not** superseded.

## Alternatives considered

- HTTP/2 on the client-facing proxy hop: rejected (D26).
- In-tree h2 codec: rejected; `x/net/http2` behind `http2x` is the 1.1 plan (D28).
- Third-party MITM library to get HTTP/2: rejected. D7 stands.

## Review triggers

Review when `golang.org/x/net/http2` is added, when inner CONNECT policy changes, or when a second Dial site is proposed inside `http2x`.

## Notes (1.2)

[ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) supersedes **D26 hop list**: client-facing may be h2c when `protocols.http2.clientCleartext`. Flag-off keeps the 1.0/1.1 PRI hard close.

[ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) supersedes **D48 Extended CONNECT / `:protocol=websocket` sentence only**. Nested inner CONNECT without `:protocol` still RST, **no flow**. Illegal h2 `Upgrade: websocket` still RST, **no flow**.

[ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) supersedes **D32 origin lock**: origin ALPN may include `h2` when `protocols.http2.origin` and the inner leaf negotiated `h2`. Still one CONNECT = one origin TCP. Flag-off keeps D32/D44 transcode.

Remainder of this ADR stands. **D7 stands.**
