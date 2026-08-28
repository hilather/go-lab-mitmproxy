# ADR 0017: HTTP proxy 407 (D76)

Status: Accepted
Date: 2026-08-28
Decisions: D76
Issue: [#52](https://github.com/hilather/go-lab-mitmproxy/issues/52) (407 proxy auth on the data plane)
Plan: [docs/tasks/plans/qa-407-proxy-auth.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/tasks/plans/qa-407-proxy-auth.md)

## Context

D17 ([docs/01-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/01-architecture.md)) and ADR [0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) D60 left the HTTP hop unauthenticated. SOCKS user-pass is a separate Reset-only plane. Issue #52 needs corp-proxy Basic simulation on `listeners.proxy`, live via REST/MCP, default-off, deterministic.

ADR [0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) `setFeature` is boolean-only and must not grow a credential body. `replaceRules` cannot 407 CONNECT (no request-phase hook) and must not 407 inner intercept.

ADR **0014** / **D69** is QA block modes. ADR **0015** / **D72–D74** is WebSocket frame rules. ADR **0016** / **D75** is rules throttle (`docs/adr/0016-rules-throttle-action.md`, merged as `1306de31`). This file is the next free ADR on `main` (**0017**). Decision number **D76** is the first unused D-number after ADR 0016 (D75). D70 remains unused by this document (throttle reserved it for an earlier 407 draft). This ADR does not overwrite block modes, websocket frame rules, or throttle.

## Decision

**D76 — Opt-in HTTP proxy authentication on the forward-proxy hop only.**
Schema `spec.proxy.httpAuth` (default `enabled: false`). Live apply verb `replaceHTTPAuth` (8th `KnownOp`). File-ref users compiled into snapshot side table `HTTPAuthUsers` (not Canonical, not export). Digest = `SHA-256(uint8(len(user)) || user || uint8(len(pass)) || pass)`, same construction as `DigestSOCKSUser`. Constant-time compare against every digest. Basic only (RFC 7617). Management stays bearer (D6).

Check after hop classification / hop gates, before Hijack, before `resolveThenGuard` / Dial. HTTP/1.1 407 via `ResponseWriter` with a determinate `Content-Length`; never Hijack a 407 CONNECT (D19). h2c RFC 9113 CONNECT: read `Proxy-Authorization` from `Stream.Headers` (`h2cConnectRequest` today copies no headers); return `Tunnel{Status:407, Headers:[{proxy-authenticate,…}]}` — no AfterAck, no Origin, do not call `writeProxyAuthChallenge` (no `ResponseWriter`). Orig-dest, inner intercept, SOCKS, Replay, h2c Extended CONNECT (`:protocol=websocket`): out.

Live Compile wiring (today cannot do this — must change it):
`compileCandidate` must receive the op list. Set `CompileOpts.ReloadHTTPAuth` iff `Previous==nil` OR any op is `replaceHTTPAuth`. `validateForCompile`: live compile always `skipUserPassFiles=true` (D60); `skipHTTPAuthFiles=!ReloadHTTPAuth`. `ValidateLiveApply(st)` as written (no options) is insufficient. Start/Reset always load files. Other live ops copy `Previous.HTTPAuthUsers`.

Reopens ADR 0012 **K10** for one additive compact status key: `features.httpAuth`. Does not grow `features.get` (11 rows). Does not add a `setFeature` ID.

Does not supersede: D6, D7, D12, D16, D19, D20, D21, D51' remainder (1.2 nested flags including `acceptUserPass` stay Reset-only), D60, D69, D72–D75.

## Consequences

- Empty `spec {}` remains an unauthenticated HTTP hop.
- Overlay examples stay `httpAuth.enabled` false.
- Catalog stays 31 `/v1` rows. No new capability IDs.
- `features.get` stays 11 rows. `setFeature` honor list unchanged.
- `KnownOp` grows `replaceHTTPAuth`; `anyLiveFeatureOp` includes it (`live_next_connection`). docs/06 apply-verb table is the operator contract (8th row).
- HTTP 407 is not a network boundary (same sentence as D60).
- D7 stands.

## Alternatives considered

- `setFeature` `proxy.httpAuth` boolean: rejected as primary (no realm/users).
- `replaceRules` `status:407`: rejected (CONNECT gap; post-DNS; inner false-positive).
- `replaceAdmission`: rejected (wrong object).
- Reuse SOCKS `userPass.users`: rejected (Reset-only D60 plane).
- Management Basic: rejected (D6).
- Drive-by `status.features.httpAuth` without reopening K10: rejected.

## Review triggers

Review when Digest / NTLM / Negotiate, sharing SOCKS and HTTP user files by reference, 407 on orig-dest / inner intercept / Replay / h2c Extended CONNECT, a Status Features toggle, or a `setFeature` ID for HTTP auth is proposed.
