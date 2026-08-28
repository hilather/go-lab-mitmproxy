# Plan: QA 407 proxy auth on the data plane

Status: ACCEPT
Owners: Proxy, Configuration, Control Plane, Security
Last reviewed: 2026-08-28
Issue: [#52](https://github.com/hilather/go-lab-mitmproxy/issues/52) item “407 proxy auth on data plane (corp-proxy auth simulation)”; live via MCP/REST
Related ADRs: 0002 (D7, D19), 0005 (D6), 0012 (D60, D17 remainder, K10 `features` names), 0013 (D51', `setFeature`)
This plan: **ADR 0017 / D76 required** (0015 / D72–D74 is WebSocket frame rules; 0014 / D69 is QA block modes)

This document is an implementation contract. It does not implement. Stop at ACCEPT or BLOCKED after skeptic-plan-review.

## Verdict

**ACCEPT.** Sweep 1 (never skipped) + fresh skeptic round 1 REVISE (F1–F7 folded) + fresh skeptic round 2 PASS (zero blocker/major). Two round-2 minors folded below. Do not implement in this PR.

## Problem

QA needs a **corporate forward-proxy authentication simulation** on `listeners.proxy`:

1. Client sends absolute-form `http://` or HTTP `CONNECT` **without** `Proxy-Authorization`.
2. Proxy answers **407** with `Proxy-Authenticate: Basic realm="…"`.
3. Client retries with `Proxy-Authorization: Basic …`.
4. Proxy accepts a matching file-ref principal and continues the hop (or 407s again).

This is **data-plane** `Proxy-Authenticate` / `Proxy-Authorization` on `:8888`. It is **not** management `/v1` or `/mcp`. Management stays lab static bearer (D6). Do **not** add HTTP Basic on management.

Default-off. Deterministic (D12). No third-party MITM/proxy libraries (D7).

## Non-goals

- HTTP Basic / `WWW-Authenticate` on the management listener.
- Digest, NTLM, Negotiate, Kerberos, or GSSAPI.
- Reusing `internal/auth.Verifier` or management token files.
- Making SOCKS `acceptUserPass` live, or sharing SOCKS `userPass.users[]` as the HTTP table.
- 407 on orig-dest `:8890`, intercepted inner hops, Replay, or SOCKS.
- Challenge-only-never-accept as a first-class mode (existing `rules` `status: 407` covers synthetic 407 on absolute-form / inner HTTP).
- A new capability ID or a dedicated `POST /v1/features/{id}` write (ADR 0013 already rejected that).
- Growing `features.get`’s frozen 11-row catalog or opening `setFeature` to non-boolean bodies.
- Live-rebind of listener addresses or orig-dest (D51' remainder).
- 407 on client-facing h2c **Extended CONNECT** (`:protocol=websocket`). That path is `h2cWebSocketTunnel`, not RFC 9113 CONNECT. Flag-off stays RST. Document as residual.

## Knob decision

| Candidate | Decision | Why |
|---|---|---|
| **`setFeature`** | **Reject as the primary knob** | ADR 0013: `setFeature` is **boolean-only** on a **closed ID switch**. Corp-proxy auth needs `realm` + file-ref users. A boolean cannot carry that. Adding `proxy.httpAuth` as a 12th `features.get` row would thaw the frozen 11-row order and still leave credentials on another verb. |
| **`replaceRules`** | **Reject as the primary knob** | CONNECT never runs request-phase rules (`serveCONNECT` has no `matchHit`; [docs/05-rules.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/05-rules.md): “Raw CONNECT tunnels have no inner HTTP, so rules do not apply”). Absolute-form rules run **after** `resolveThenGuard` ([`internal/proxy/forward.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/proxy/forward.go)), so a `status: 407` rule is not a pre-Dial gate. Inner intercept **would** match and wrongly 407 origin-facing hops. `match.headerName` cannot express absence. Inline secrets are forbidden. |
| **`replaceAdmission`** | **Reject** | `AdmissionSpec` is session caps / timeouts. Credentials and 407 policy do not belong there. `maxConcurrentStreams` already rides this verb; do not overload it. |
| **`replaceHTTPAuth`** (new live apply verb) | **Accept** | Same family as `replaceTargets` / `replaceRules`: live snapshot swap, no Reset, no inbox wipe. Carries the full `spec.proxy.httpAuth` subtree (`enabled`, `realm`, `users[]`). No new capability ID. Mutation stays `changes.plan` / `changes.apply` (`mitm.admin`). |

Live via MCP/REST means `POST /v1/changes:plan` + `:apply` and `mitm_change_plan` / `mitm_change_apply`. That satisfies #52 without a `features.get` row or Status toggle (ADR 0013 product call 3: Status toggles `setFeature` IDs only).

Compact `GET /v1/status` `features.httpAuth` (additive boolean, default false) is **allowed only because ADR 0017 reopens ADR 0012 K10** (frozen `features` JSON names). It is **not** a drive-by “same as `acceptUserPass`.” `acceptUserPass` is already on K10 and is filled from spec in `featuresFromSpec`, not `CatalogFromSpec`. Implementers must add `httpAuth` to **both** REST and MCP `statusFeaturesJSON` and name the reopen in ADR 0017. Do **not** nest a catalog row under `status.features`. Do **not** add a Status toggle.

`listeners.proxy.acceptUserPass` stays **Reset-only** (1.2, D51' remainder, D60). HTTP 407 is a **different plane**.

## Invariant change — ADR 0017 (land with implementation)

ADR 0012’s review trigger is explicit: *“Review when … HTTP `Proxy-Authorization` … is proposed (each needs a new ADR).”* Architecture **D17 remainder** (“HTTP hop unauthenticated; no `Proxy-Authorization`”) must be superseded **only when `spec.proxy.httpAuth.enabled` is true**. Default-off empty `spec: {}` stays today’s unauthenticated HTTP hop.

**Do not write this ADR in the plan-only PR.** Implementation PR 1 lands `docs/adr/0017-http-proxy-407.md` **before** code. Draft:

```text
# ADR 0017: HTTP proxy 407 (D76)

Status: Accepted
Date: 2026-08-28
Decisions: D76

## Context

D17 (docs/01-architecture.md) and ADR 0012 D60 left the HTTP hop
unauthenticated. SOCKS user-pass is a separate Reset-only plane.
Issue #52 needs corp-proxy Basic simulation on listeners.proxy,
live via REST/MCP, default-off, deterministic.

ADR 0013 setFeature is boolean-only and must not grow a credential
body. replaceRules cannot 407 CONNECT (no request-phase hook) and
must not 407 inner intercept.

## Decision

D76 — Opt-in HTTP proxy authentication on the forward-proxy hop only.
Schema spec.proxy.httpAuth (default enabled: false). Live apply verb
replaceHTTPAuth (8th KnownOp). File-ref users compiled into snapshot
side table HTTPAuthUsers (not Canonical, not export). Digest =
SHA-256(uint8(len(user)) || user || uint8(len(pass)) || pass), same
construction as DigestSOCKSUser. Constant-time compare against every
digest. Basic only (RFC 7617). Management stays bearer (D6).

Check after hop classification / hop gates, before Hijack, before
resolveThenGuard / Dial. HTTP/1.1 407 via ResponseWriter with a
determinate Content-Length; never Hijack a 407 CONNECT (D19).
h2c RFC 9113 CONNECT: read Proxy-Authorization from Stream.Headers
(h2cConnectRequest today copies no headers); return
Tunnel{Status:407, Headers:[{proxy-authenticate,…}]} — no AfterAck,
no Origin, do not call writeProxyAuthChallenge (no ResponseWriter).
Orig-dest, inner intercept, SOCKS, Replay, h2c Extended CONNECT
(:protocol=websocket): out.

Live Compile wiring (today cannot do this — must change it):
compileCandidate must receive the op list. Set
CompileOpts.ReloadHTTPAuth iff Previous==nil OR any op is
replaceHTTPAuth. validateForCompile: live compile always
skipUserPassFiles=true (D60); skipHTTPAuthFiles=!ReloadHTTPAuth.
ValidateLiveApply(st) as written (no options) is insufficient.
Start/Reset always load files. Other live ops copy
Previous.HTTPAuthUsers.

Reopens ADR 0012 K10 for one additive compact status key:
features.httpAuth. Does not grow features.get (11 rows).
Does not add a setFeature ID.

Does not supersede: D6, D7, D12, D16, D19, D20, D21, D51' remainder
(1.2 nested flags including acceptUserPass stay Reset-only), D60.

## Consequences

- Empty spec {} remains an unauthenticated HTTP hop.
- Overlay examples stay httpAuth.enabled false.
- Catalog stays 31 /v1 rows. No new capability IDs.
- features.get stays 11 rows. setFeature honor list unchanged.
- KnownOp grows replaceHTTPAuth; anyLiveFeatureOp includes it
  (live_next_connection). docs/06 apply-verb table is the operator
  contract (8th row).
- HTTP 407 is not a network boundary (same sentence as D60).
- D7 stands.

## Alternatives considered

- setFeature proxy.httpAuth boolean: rejected as primary (no realm/users).
- replaceRules status:407: rejected (CONNECT gap; post-DNS; inner false-positive).
- replaceAdmission: rejected (wrong object).
- Reuse SOCKS userPass.users: rejected (Reset-only D60 plane).
- Management Basic: rejected (D6).
- Drive-by status.features.httpAuth without reopening K10: rejected.
```

Decision number **D76** (0014 / D69 is QA block modes; 0013 used D51' / D22 carve).

## Wire semantics

### Where it runs

| Entry | 407? | Notes |
|---|---|---|
| Forward-proxy HTTP `CONNECT` | **yes** | Two windows, do not conflate. `protocols.connect` 403 is in `ServeHTTP` **before** `metrics.accept()` ([`handler.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/proxy/handler.go) 52–70). Port parse + Hijack are **after** accept, first lines of `serveCONNECT`. **Contract (A):** check auth in `serveCONNECT` after `host:port` (400 still wins), **before Hijack**, increment `reject("proxy_auth")`, do **not** move `metrics.accept()` and do **not** claim 407 is pre-accept. Missing-port CONNECT today is already accept+400; leave that. |
| Absolute-form `http://` | **yes** | After websocket / `absoluteForm` gates, **before** `resolveThenGuard`. Post-`metrics.accept()` (ServeHTTP already accepted). |
| Absolute-form `https://` | **no** | Stays 400 `absolute_https`. |
| Origin-form on `:8888` | **no** | Stays 400 `absolute-form or CONNECT required`. |
| Orig-dest origin-form / tagged CONNECT | **no** | Not a proxy hop (D31 / D57). |
| PRI flag-off | **no** | Hard close `reason=http2` before acquire. |
| Client-facing h2c regular GET/POST | **yes** | `reconstructH2Request` copies `in.Headers` (including `proxy-authorization`). Then `serveAbsolute`. Auth sees the header. `http2x.writeResponse` does **not** strip `proxy-authenticate` (only `proxy-authorization` is in `hopHeaders`). Session `metrics.accept()` already ran once per TCP in `serveH2C`. |
| Client-facing h2c RFC 9113 CONNECT | **yes** | **Accept must work.** `h2cConnectRequest` today builds `Header: make(http.Header)` and copies **no** fields — checking `req.Header` is permanent 407 (forbidden non-goal). Read `in.Headers` (or copy `proxy-authorization` onto the synthetic request) **before** Dial. Return `http2x.Tunnel{Status: 407, Headers: [{Name: "proxy-authenticate", Value: "Basic realm=…"}]}`. `writeStatus` will emit it (`proxy-authenticate` is not in `hopHeaders`). No AfterAck, no Origin, **do not** call `writeProxyAuthChallenge`. Add an h2c CONNECT **success/retry** test, not only 407. Post-session-accept (`serveH2C` accepts once per TCP). |
| Client-facing h2c Extended CONNECT | **no** | Residual. `h2cWebSocketTunnel` is not this feature. |
| Intercepted inner HTTP/1.1 or h2 | **no** | CONNECT already authenticated. Inner `Proxy-Authorization` stays hop-by-hop stripped. |
| SOCKS | **no** | `acceptUserPass` / RFC 1929 only. |
| Replay | **no** | Operator origin fetch (D21). |

### Challenge and accept

When `sess.spec.Proxy.HTTPAuth.Enabled` (name TBD in model: `HTTPAuth`):

```text
if missing / non-Basic / bad base64 / no digest match:
    write 407
    Proxy-Authenticate: Basic realm="<realm>"
    do not Hijack
    do not Dial / LookupIP
    capture metadata flow Status=407 Error=proxy_auth (no username/password)
    metric labmitm_proxy_rejected_total{reason="proxy_auth"}
    (must add "proxy_auth" to observability.ProxyRejectReason — unknown
    tokens collapse to "admission"; docs/11 alone is not enough)
    return
else:
    continue existing hop
    optional Flow annotation: matching YAML id only (never username/password)
```

- Realm: YAML string; empty materializes `labmitm-proxy` (must not equal management `Bearer realm="labmitm"`).
- Compare: decode Basic `user:pass`, digest, constant-time against **every** `HTTPAuthUsers` entry (same as SOCKS D60).
- Fail-closed: `enabled: true` with zero users is `validation_failed`.
- File refs only. First non-comment line 1–255 bytes. User `id` unique `[a-z0-9-]{1,64}`. Duplicate credential digests rejected.
- `Proxy-Authorization` remains hop-by-hop stripped on the origin hop ([`internal/httputilx`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/httputilx/hop.go)). Never forward it.
- Never log / export / attach username, password, or raw `Proxy-Authorization`.
- **Do not** use `writeProxyError` for 407: it sets `Connection: close` and writes a body **without** `Content-Length` ([`internal/proxy/error.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/proxy/error.go)). RFC 9112: no length and no chunked ⇒ the message ends by closing the connection. Deleting only `Connection: close` is not keep-alive. New helper `writeProxyAuthChallenge`: HTTP/1.1 407, `Proxy-Authenticate: Basic realm="…"`, short `text/plain` body, **mandatory `Content-Length`**, omit `Connection: close`. Do not emit chunked (PlayTranscript is line-exact; many CONNECT clients mishandle TE on 407).
- D19: only Hijack when proceeding to the tunnel. A 407 CONNECT stays with `http.Server`.
- Admission still runs first (429/503 beats 407). HTTP/1.1 hop-disable 403 beats 407. **h2c CONNECT does not honor `protocols.connect`** (docs/02); it can 407 while HTTP/1.1 CONNECT 403s. Document that. Do not call a shared `checkHTTPAuth` from `forwardOriginHTTP` / `roundTripInner` (inner false-positive).
- In-flight CONNECT keeps the pinned snapshot (ADR 0013 `live_next_connection`). Next `ServeHTTP` / h2c stream sees the swap.
- HTTP 407 is **not** a substitute for a network boundary (D10 / D60 wording).

### CONNECT vs absolute-form (explicit)

Both legal forward-proxy hops on `listeners.proxy` share one policy. Differences:

- **CONNECT:** 407 **instead of** `200 Connection Established`. After success, existing Hijack + 200 + intercept/tunnel. ClientHello must never be parsed as HTTP (existing `connect-hijack` transcript still holds when auth is off or already satisfied).
- **Absolute-form:** 407 **instead of** origin `RoundTrip`. After success, existing origin-form forward + hop-by-hop strip.
- Keep-alive: absolute-form retry is a second `ServeHTTP` on the same TCP if 407 did not close. CONNECT retry is a second CONNECT request on the same TCP (not Hijacked).

### Interaction with existing `rules` `status: 407`

`action.status` already allows 400–599. Leave it. It remains a **synthetic origin-like response** after DNS on absolute-form / inner HTTP. It does **not** become proxy auth. Docs must say so (do not invent a `proxyAuth` rule action).

## Schema and compiler

Additive `labmitm.dev/v1alpha1` (D22). Legal camelCase `httpAuth` (normalize `httpauth` — not reserved). Do not name it `socks*` / `proxyauthorization` as a config key.

```yaml
spec:
  proxy:
    httpAuth:
      enabled: false          # default; empty spec {} stays false
      realm: ""               # empty → labmitm-proxy
      users: []               # file refs; required ≥1 when enabled
        # - id: lab-proxy
        #   usernameFile: /run/secrets/proxy-user
        #   passwordFile: /run/secrets/proxy-pass
```

Reuse the `UserPassUserSpec` **shape** (do not invent a second secret-file struct). Do **not** reuse `validateUserPassUsers` — it hardcodes `spec.listeners.proxy.userPass.users`. New helper with `spec.proxy.httpAuth.users[i]` paths.

JSON Schema is **hand-maintained** and `$defs.proxy` is `additionalProperties: false` with only `hostname` / `admission` / `targets` today. A dangling `$defs.httpAuth` that is not referenced from `$defs.proxy.properties` is rejected by the published schema. Required:

- `"httpAuth": { "$ref": "#/$defs/httpAuth" }` on `$defs.proxy.properties`
- `$defs.httpAuth` + reuse `$defs.userPassUser` (or inline the same three fields)
- add `httpAuth` to the `$defs` required list in [`internal/config/schema_test.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/config/schema_test.go)
- `ProxySpec` field walk already fails if the JSON tag is missing from the schema

`replaceHTTPAuth` body is the `httpAuth` object. `KnownOp` grows an **8th** verb (`internal/model/operation.go` is a closed switch; docs/06 apply-verb table is the operator contract). `Operation` grows one field. **`anyLiveFeatureOp` must include `replaceHTTPAuth`** so plan warns `live_next_connection`.

Compiler (today’s wiring cannot implement the flag — change it):

- Snapshot field `HTTPAuthUsers []SOCKSUserDigest` (or a renamed shared `UserDigest` type). Never Canonical, never `GET /v1/state` / export.
- [`compileCandidate`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/app/svc.go) currently passes `CompileOpts{Now, Previous: prev}` with **no ops**. It must take the op list (or a bool) and set `ReloadHTTPAuth` iff `Previous == nil` **or** any op is `replaceHTTPAuth`.
- `validateForCompile` today is only `Previous != nil → ValidateLiveApply(st)`. `ValidateLiveApply` takes **no options** and hardcodes `skipUserPassFiles: true`. Split: live compile always `skipUserPassFiles: true` (D60); `skipHTTPAuthFiles: !ReloadHTTPAuth`. Thread `skipHTTPAuthFiles` into `validateProxy` (it currently takes no `validateOpts`); file checks may live only in the compiler if that matches the SOCKS split.
- Start/Reset call `compiler.Compile` with `Previous == nil` and **never** go through `compileCandidate`. File reload must treat `Previous == nil` inside Compile, not only a flag `compileCandidate` sets.
- If HTTP auth is implemented like SOCKS (`Previous != nil` ⇒ copy digests always), `replaceHTTPAuth` updates Canonical paths and **keeps old digests** — live credential apply is a no-op. Forbidden.
- `replaceRules` / `setFeature` / `replaceTLS` + vanished HTTP auth files must not fail (copy Previous).

Reserved-key fixtures: `httpAuth` is legal; `proxy-authorization` as a **config section** fails KnownFields; do not add it to `reservedExact` unless a test wants a reserved alias — prefer KnownFields.

Overlay [`examples/labmitm.yaml`](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/labmitm.yaml) stays `httpAuth` off / omitted.

## Control plane and parity

- **No new capability ID.** `TableRowCount` stays **31**. `features.get` stays **11** rows. `setFeature` honor list unchanged (unknown `proxy.httpAuth` remains `validation_failed`).
- Existing `changes.plan` / `changes.apply` / `mitm_change_*` grow the op. Shared domain types in `internal/model` + `internal/app`. Adapters must not reimplement compile.
- Compact `status.features.httpAuth` on **both** REST and MCP `statusFeaturesJSON` copies (lockstep, same as 1.2 keys). Derived from `spec.proxy.httpAuth.enabled`, **not** from `CatalogFromSpec` (that catalog stays hop/protocol gates).
- `GET /v1/state` redacts user file **contents** (paths may appear, like SOCKS). Export never includes usernames, passwords, or digests.
- Audit `changes.apply` records op + actor; not secrets.
- Parity: REST contract + MCP protocol tests for the new op; `make test-parity` (no new `PARITY_REQUIRED` row).
- UI: no Status toggle. Optional later: show the compact boolean on Status — **out of this plan** unless a one-line badge is free. Do not add a `/features` row.

## Security

| Rule | Detail |
|---|---|
| D6 | Management `401` + `WWW-Authenticate: Bearer realm="labmitm"`. Never 407 / Basic / `Proxy-Authenticate` on `/v1` or `/mcp`. |
| D17 remainder | Superseded **only** when `httpAuth.enabled`. Flag-off process is unchanged. |
| D10 | Default bind loopback. 407 is not a published-bind license. |
| D16 | Auth failure never `LookupIP` / Dial. Success still resolve-then-guard every A/AAAA. |
| D19 | 407 CONNECT is not Hijacked. |
| D12 | No random realm, no probabilistic challenge, no jitter. |
| D7 | Stdlib only. |
| Secrets | File refs; digest side table; zeroize file bytes after hash (SOCKS helper). Do not reuse `Verifier`. |
| Open proxy | Document: enabling 407 on a LAN publish is still operator risk; default-deny metadata/link-local still apply after accept. |

## Implementation sequence (later; not this PR)

1. Land ADR 0017 + numbered-pack D17/D76 edits + known-limitations residual rewrite.
2. Model / schema / validate / normalize / testdata valid+invalid+reserved.
3. Compiler `HTTPAuthUsers` + `ReloadHTTPAuth`. Change `compileCandidate` to take ops. Change `validateForCompile` / `ValidateLiveApply` options. Vanish-file tests (mirror `internal/compiler/socks_test.go`) plus “replaceHTTPAuth must not keep stale digests.”
4. `replaceHTTPAuth` in `internal/app` (plan/apply/idempotency/CA reuse/inbox not wiped; `anyLiveFeatureOp`).
5. Proxy helper + CONNECT / absolute-form / h2c hooks + `writeProxyAuthChallenge`.
6. proxytest transcripts + unit tests listed below.
7. REST/MCP DTO lockstep + contract + `make test-parity`.
8. Observability: add `proxy_auth` to `internal/observability/labels.go` `ProxyRejectReason` (closed switch; unknown → `admission`) and docs/11. Generate metrics JSON only if that catalog enumerates reasons.
9. CHANGELOG unreleased + docs/02, 06, 07, 10, 12, 14 note, examples comments.

## Tests (implementation must add)

Bug-fix / new-behavior rule: failing test first.

### proxytest / `internal/proxy`

Transcripts under `testdata/proxy/` (PlayTranscript):

- `http-auth-absolute-407.txt` — enabled, no header → 407 + `Proxy-Authenticate: Basic realm="labmitm-proxy"`; origin not contacted.
- `http-auth-absolute-ok.txt` — second request on same TCP (or follow-up script) with valid Basic → 200 origin-form; origin `Proxy-Authorization` absent (hop-by-hop).
- `http-auth-connect-407.txt` — CONNECT without creds → 407, **no** `200 Connection Established`, origin not dialed. Must fail if Hijack-then-407 is implemented.
- `http-auth-connect-retry.txt` — 407 then CONNECT + Basic on the **same** TCP → 200 + tunnel. Transcript must see `Content-Length` on the 407 and must **not** see `Transfer-Encoding: chunked`. Existing `connect-hijack.txt` still green when `enabled: false`.
- `http-auth-off.txt` — empty/`enabled: false` + stray `Proxy-Authorization` → existing unauthenticated success; header still stripped upstream.

Go tests (`internal/proxy`, not necessarily PlayTranscript):

- Wrong password / non-Basic scheme / garbage base64 → 407, no Dial.
- CONNECT missing port still 400 (auth not consulted).
- `protocols.connect.enabled: false` still 403 (not 407).
- Orig-dest origin-form with `httpAuth.enabled` → **no** 407, dest-IP Dial only.
- Inner intercept GET with `httpAuth.enabled` → **no** 407 (CONNECT already authed).
- h2c GET 407 then retry with Basic → origin GET, no `proxy-authorization` upstream (`clientCleartext` on).
- h2c RFC 9113 CONNECT 407 HEADERS (no Dial), then a **second CONNECT stream** (or same-session retry) with `proxy-authorization` copied from `in.Headers` → tunnel/intercept. Must fail if `h2cConnectRequest` empty-header bug is left in place.
- h2c Extended CONNECT (`:protocol=websocket`) is **not** 407’d by this feature (RST/existing path).
- HTTP/1.1 `protocols.connect.enabled: false` still 403; h2c CONNECT may still 407 (document; do not silently apply the 403 gate). Put the h2c auth check in `h2cConnectTunnel` **after** the `:protocol` branch, not at `h2cTunnel` entry (Extended CONNECT stays out).
- `anyLiveFeatureOp` including `replaceHTTPAuth` is a product choice: rewrite the docs/06 sentence that only `setFeature` / `replaceCompat` warn `live_next_connection`, and add a positive warning test (`TestPlanReplaceRulesHasNoLiveNextConnection` treats subtree replaces as silent today).
- Live `replaceHTTPAuth` enabled flip: next absolute-form 407; in-flight CONNECT (already 200) not torn down.
- SOCKS `acceptUserPass` unchanged when HTTP auth is on.
- Management `/v1/flows` without bearer still 401 (existing); never 407.
- `writeProxyError` path unchanged for 403/400/429.

### Config / compiler / app

- Valid: enabled + one user; disabled + users present; empty spec `enabled: false`.
- Invalid: enabled and `users: []`; bad id; missing files at Start; reserved `socks*` still reserved.
- Normalize: empty realm → `labmitm-proxy`; empty users slice not nil.
- Revision hash: file **paths** in spec, never digest bytes.
- `replaceHTTPAuth` live stats files; vanished file fails **that** op only.
- `replaceRules` after vanished HTTP auth file **succeeds** (copy Previous).
- Reset reloads new file bytes.
- `setFeature` of `proxy.httpAuth` stays `unknown feature id`.
- Catalog `TableRowCount == 31`; `GET /v1/features` still 11 items.

### REST / MCP parity

- `changes:plan` / `:apply` / `mitm_change_*` with `replaceHTTPAuth`.
- `revision_conflict`, idempotency, `live_next_connection` warning.
- Status compact `features.httpAuth` false by default; true after apply. REST and MCP private structs lockstep (`dto_test` / MCP equivalent).
- Export / `state.get` contain no password bytes / digests.
- Unauthenticated `GET /v1/flows` 401 + `WWW-Authenticate: Bearer` (existing).

## Documentation (implementation PR)

| Doc | Change |
|---|---|
| `docs/adr/0017-http-proxy-407.md` | New |
| `docs/adr/0012-…` | Review-trigger note: HTTP Proxy-Authorization landed as 0017; K10 list additively names `httpAuth` (reopen is 0017) |
| `docs/01-architecture.md` | D17 remainder + D76; non-goal line |
| `docs/02-proxy-semantics.md` | Classification table + 407 writer + CONNECT-before-Hijack + metrics contract (A) |
| `docs/05-rules.md` | `status: 407` is not proxy auth |
| `docs/06-state-and-configuration.md` | Schema, 8th apply verb `replaceHTTPAuth`, live vs SOCKS file stat |
| `docs/07-control-plane-and-parity.md` | Compact `features.httpAuth` (K10 reopen via 0017); catalog still 31; `features.get` still 11 |
| `docs/08-rest-api.md` | Apply op (no new path) |
| `docs/10-security-architecture.md` | HTTP hop row; D6 unchanged |
| `docs/11-observability.md` | `reason=proxy_auth` |
| `docs/12-testing-strategy.md` | New transcripts |
| `docs/14-integration-lab.md` | Overlay note stays “no Proxy-Authorization” until an overlay opts in (it must not) |
| `docs/known-limitations.md` | Remove “HTTP hop unauthenticated” as an absolute; state default-off + D76 |
| `docs/README.md` | ADR 0017 row |
| `CHANGELOG.md` | Unreleased |
| `AGENTS.md` | D17/D76 sentence; do not claim catalog 30 |

Last-reviewed dates on every substantively edited doc.

## Sweep 1 — author (never skipped)

Verified against `origin/main` `701a163` (v1.3.0 notes present).

| Claim | Evidence | Result |
|---|---|---|
| `setFeature` exists and is boolean-only | [`docs/adr/0013-live-protocol-feature-gates.md`](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) “`setFeature` is boolean-only”; [`internal/model/operation.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/model/operation.go) `FeaturePatch`; [`internal/app/operations.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/app/operations.go) `applySetFeature` closed switch | Hold |
| `features.get` is 11 frozen rows; catalog 31 | ADR 0013; [`internal/app/features.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/app/features.go) `CatalogFromSpec`; [`internal/control/rest/contract_test.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/control/rest/contract_test.go) `len(items) != 11`; docs/07 `TableRowCount` 31 | Hold |
| Next ADR is **0017** (0015 is WebSocket frame rules / D72–D74) | [`docs/adr/0015-websocket-frame-rules.md`](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0015-websocket-frame-rules.md) | Hold — implementation retargeted after #61 merged |
| D17 remainder + ADR 0012 review trigger still forbid HTTP `Proxy-Authorization` | docs/01 D17; ADR 0012 “Does not supersede … D17 remainder”; known-limitations “HTTP `Proxy-Authorization`” | Hold — ADR required |
| CONNECT has no request-phase rules | [`internal/proxy/connect.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/proxy/connect.go) `serveCONNECT`; docs/05 | Hold — `replaceRules` cannot be the primary knob |
| Absolute-form rules run after DNS | [`internal/proxy/forward.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/proxy/forward.go) `resolveThenGuard` then `forwardOriginHTTP` → `matchHit` | Hold |
| CONNECT Hijack is immediate after port check | [`internal/proxy/connect.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/proxy/connect.go) | Hold — 407 must be inserted **before** `Hijack` |
| CONNECT disable 403 is before Hijack / before `metrics.accept()` | [`internal/proxy/handler.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/proxy/handler.go) | Hold for 403. **Revised:** 407 uses contract (A) in `serveCONNECT` after port parse — post-accept, pre-Hijack. Do not call that the 403 window. |
| `writeProxyError` always `Connection: close` | [`internal/proxy/error.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/proxy/error.go) | Hold — dedicated 407 writer required |
| Hop-by-hop already strips `Proxy-Authorization` | [`internal/httputilx/hop.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/httputilx/hop.go) | Hold |
| `action.status` already allows 407 | [`internal/config/validate.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/config/validate.go) 400–599 | Hold — leave as orthogonal |
| SOCKS files: live apply copies, Start/Reset stats | [`internal/compiler/socks.go`](https://github.com/hilather/go-lab-mitmproxy/blob/main/internal/compiler/socks.go); `ValidateLiveApply` `skipUserPassFiles` | Hold — HTTP auth must not reuse that blindly on `replaceHTTPAuth` |
| JSON Schema `proxy` has only hostname/admission/targets | [`api/jsonschema/labmitm.dev.v1alpha1.json`](https://github.com/hilather/go-lab-mitmproxy/blob/main/api/jsonschema/labmitm.dev.v1alpha1.json) | Hold — additive `$defs.httpAuth` |
| Management has no Basic | docs/10; ADR 0005; docs/08 | Hold |
| `acceptUserPass` is Reset-only | ADR 0013 table; docs/06 | Hold — do not live-apply SOCKS user-pass as a side effect |
| No `docs/tasks/plans/` on main | glob empty | Hold — this file is new |

Sweep 1 found **no blocker** at author time. Stale assumption “`setFeature` does not exist” is **false** on v1.3.0; the plan treats it as existing and **rejects it as the primary 407 knob**.

Skeptic round 1 (fresh) verdict **REVISE**: F1 h2c CONNECT empty-header accept hole (blocker); F2 accept-window conflation; F3 407 without `Content-Length`; F4 `compileCandidate` cannot set `ReloadHTTPAuth`; F5 K10 reopen required for compact `features.httpAuth`. F6/F7 schema-ref + 8th `KnownOp` (minor). All folded into this revision.

## Skeptic review trail

| Round | Role | Verdict | Findings |
|---|---|---|---|
| 1 | Author sweep 1 | continue | See table above |
| 1 | Fresh skeptic | REVISE | F1 blocker (h2c CONNECT headers); F2–F5 major; F6–F7 minor |
| 2 | Author revision | folded | Contract (A); Content-Length; compileCandidate+ops; K10; h2c accept test |
| 2 | Fresh skeptic | **PASS** | F1–F7 FIXED; two minors (ProxyRejectReason switch; docs/06 warning sentence) |
| 2 | Author fold minors | ACCEPT | labels.go + docs/06 warning test + Start/Reset Previous==nil + h2c hook placement |

**Cap 3.** Unresolved blocker after round 3 → **BLOCKED** (do not implement).

## Out of scope leftovers (do not silently expand)

- Status Features toggle for HTTP auth.
- `setFeature` ID `proxy.httpAuth`.
- Digest / NTLM.
- Sharing SOCKS and HTTP user files by reference.
- 407 as an admission or rule action type.
- UI login-style proxy-auth page.
- h2c Extended CONNECT (`:protocol=websocket`) 407.
- Moving `metrics.accept()` so 407 is pre-accept (rejected; contract A).

## Plan-only PR contents

This PR adds this file and indexes it from `docs/README.md`. It does **not** add ADR 0017, schema, or code.
