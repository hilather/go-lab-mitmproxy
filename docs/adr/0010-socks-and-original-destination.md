# ADR 0010: SOCKS5 multiplex and original-destination REDIRECT

Status: Accepted
Date: 2026-08-19
Decisions: D29, D30, D31, D34, D38, D42, D49, D50, D55, D56, D57

## Context

ADR 0002 said reverse-proxy, TPROXY, and SOCKS are 1.1+. 1.0 peeks one byte and closes `0x04`/`0x05`. Labs that cannot set an HTTP proxy have no path; origin-form on `:8888` stays `400`.

Linux **TPROXY** / `IP_TRANSPARENT` / `CAP_NET_ADMIN` would break the UID 65532 scratch image. Transparent intercept, if any, must be **REDIRECT + `SO_ORIGINAL_DST`** on a separate listener, with iptables in a privileged sidecar or on the host.

This ADR supersedes ADR 0002’s **“TPROXY and SOCKS are 1.1+” sentence** only. **TPROXY stays rejected** (`tproxy` remains reserved). Reverse-proxy stays rejected. **D7 stands.**

## Decision

**D29 — SOCKS5 CONNECT, NO AUTH, multiplexed on the proxy listener.** `acceptSOCKS5` default false. `acceptSOCKS4` separate, default false. BIND, UDP ASSOCIATE, GSSAPI, and username/password stay out (D17).

**D30 — Transparent = Linux REDIRECT + `SO_ORIGINAL_DST`, separate listener.** Not TPROXY. Default image stays UID 65532, `cap_drop: ALL`.

**D31 — Origin-form is legal only on the original-destination listener** when dest was recovered. Proxy listener origin-form stays `400`.

**D34 — Hairpin guards extend to every live data-plane bind.**

**D38 — Orig-dest default `127.0.0.1:8890`.** Empty address materializes that, not `:8890`.

**D42 — Accept mux never peeks on the Accept goroutine.** Peek runs in a per-conn goroutine (or peek-on-first-Read). Silent peer must not stall Accept.

**D49 — Orig-dest TLS parses ClientHello (SNI+ALPN) with byte replay**, then decides intercept. Do not branch on first byte `'P'`.

**D50 — Supported orig-dest topologies only:** shared netns + sidecar iptables, or host network + host REDIRECT. Publishing `8890` is not transparent.

**D55 — `gate.acquire` once per orig-dest TCP.**

**D56 — Ready mirrors management:** `OrigDestBound` or `OrigDestOff`.

**D57 — Orig-dest splice in `ServeHTTP` is after acquire and before the 1.0 CONNECT / `serveAbsolute` ladder.** Tagged conns Dial dest IP:port only.

Flags default off. The D42 accept mux peeks in a per-conn goroutine and still SOCKS-closes `0x04`/`0x05` while the flags are false. SOCKS serve and orig-dest bind are later workstreams. `serveInterceptConn` is the shared intercept entry (no HTTP 200).

## Consequences

- 1.0 SOCKS-close and origin-form-400 transcripts stay green while flags are off.
- Reserved `socks*` / `tproxy` / `transparent` keys stay reserved. Legal YAML is `acceptSOCKS5` / `originalDestination`.
- D7 is **not** superseded.

## Alternatives considered

- TPROXY / `CAP_NET_ADMIN` on the appliance: rejected (D30).
- Multiplex orig-dest onto `:8888`: rejected; separate listener (D30, D38).
- Peek on the Accept loop: rejected (D42); reintroduces the stall 1.0 already avoided.

## Review triggers

Review when BIND/UDP ASSOCIATE is proposed, when a non-Linux orig-dest path is requested, or when TPROXY is reconsidered (it would need a new ADR and must not land in the default image).
