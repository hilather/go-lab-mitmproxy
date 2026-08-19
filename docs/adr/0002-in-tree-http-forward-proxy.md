# ADR 0002: In-tree HTTP/1.1 forward proxy

Status: Accepted
Date: 2026-08-18
Decisions: D7, D8, D16, D19, D20, D21

## Context

Family appliances own their protocol state machines (LabMail ADR 0002, TacLab ADR 0007, LabDNS `dnswire` isolation). Off-the-shelf mitmproxy is a Python attack/research tool with a plugin VM and no `labmitm.dev/v1alpha1`. Third-party Go MITM libraries make intercept policy, import boundaries, and “no HTTP/2 / no SOCKS / no random chaos” hard to prove.

Unlike LabMail (receive-only forbids Dial), a forward proxy **must** Dial. Isolation + resolved-IP guards replace “unrepresentable outbound.”

## Decision

**D7 — In-tree HTTP/1.1 forward proxy.** `internal/proxy` uses stdlib `net`, `net/http`, `bufio`. No third-party proxy library. Reverse-proxy, TPROXY, and SOCKS are 1.1+. CONNECT **must** `Hijack` before any body and never return that conn to `http.Server` (D19).

**D8 — HTTP/1.1 only on every hop in 1.0.** Client-facing proxy, intercepted inner request, and upstream origin are HTTP/1.1. Minted leaves advertise ALPN `http/1.1` only. HTTP/2 preface (`PRI * HTTP/2.0`) is a hard close.

**D16 — Data-plane Dial is required, isolated, and resolve-then-guard.** Production `Dial` / `DialTimeout` / `Dialer.Dial` / `DialContext` idents are allowed **only** in `internal/proxy` and `*_test.go` / `internal/proxytest`. Forbidden in every other `internal/*` production file, including `internal/tlsmitm`. Algorithm: parse authority → literal CIDR check or `LookupIP` then check **every** A/AAAA → Dial a selected allowed IP with no second resolve. Default-deny cloud metadata and link-local; loopback allowed.

**D19 — CONNECT Hijack + inner HTTP/1.1 session.** On `CONNECT`, `Hijack()` after headers and before any body; never return that conn to `http.Server`. One CONNECT = one upstream TCP (and at most one upstream TLS). Inner requests are serialized `http.ReadRequest` + `Transport.RoundTrip` on a one-shot `DialContext`.

**D20 — `intercept: true` does not silently tunnel.** Handshake failure closes both sides and stores `Error=tls_handshake` / `upstream_tls`. CONNECT to a matching host on a non-listed port is a raw tunnel (`intercepted=false`).

**D21 — `Transport.RoundTrip` only; no `http.Client`.** `CheckRedirect` unused. Replay Dials the **origin**, ignores `HTTP_PROXY`, never hairpins `listeners.proxy.address`.

## Consequences

- Every request class and reject reason is listed in [docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md).
- Dial isolation can be proven with import-boundary tests.
- More session code than a library wrap.
- HTTP/2 intercept is the leading 1.1 candidate, not a 1.0 slip.

## Alternatives considered

- Wrap or exec Python mitmproxy: rejected (plugin VM, no YAML/capability registry, cannot be scratch/non-root).
- Third-party Go MITM library: rejected for 1.0. Revisit only if PR 3–4 interop is still red at rc, vendored behind `internal/proxy` via a new ADR.
- Reverse-proxy / transparent TPROXY as the 1.0 posture: rejected. Requires `CAP_NET_ADMIN` and breaks the hardened image contract.
- HTTP/2 intercept in 1.0: rejected. Would force `golang.org/x/net/http2` or a lying capture.
- `http.Client` / follow-redirects / hairpin replay: rejected. `Client.Do` merges hops and would honor `HTTP_PROXY`.

## Review triggers

Review this decision when PR 3–4 interop is still red at rc, HTTP/2 intercept is accepted as 1.1 work, or a second Dial site is proposed outside `internal/proxy`.

## Notes (1.1)

[ADR 0009](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0009-http2-via-http2x.md) supersedes **D8 scope only**: HTTP/2 may be enabled on the intercepted inner hop and origin hop via `protocols.http2` (default off). Client-facing proxy hops stay HTTP/1.1; `PRI * HTTP/2.0` remains a hard close.

[ADR 0010](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0010-socks-and-original-destination.md) supersedes the sentence “Reverse-proxy, TPROXY, and SOCKS are 1.1+” insofar as SOCKS5 CONNECT and Linux original-destination REDIRECT become 1.1 opt-in. **TPROXY stays rejected.** Reverse-proxy stays rejected.

**D7 stands.** The proxy remains in-tree. Third-party MITM/proxy libraries stay forbidden. CONNECT still Hijacks (D19). D16, D20, and D21 stand.
