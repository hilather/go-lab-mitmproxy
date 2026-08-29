# REST API

Status: Proposed normative behavior
Owners: REST, Application
Last reviewed: 2026-08-29 (operator SPA remaining-page chrome)
Related ADRs: 0004, 0005, 0007, 0011, 0012, 0013, 0014, 0015, 0016, 0017

Base: `/v1`. JSON unless noted. Errors: `Content-Type: application/problem+json`. Capability table: [docs/07-control-plane-and-parity.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/07-control-plane-and-parity.md).

API-001 implements the native REST adapter (`internal/control/rest`) from the frozen capability registry. OpenAPI is generated (`make generate` → `api/openapi/v1.json`). SEC-001 implements cookie `labmitm_session` + CSRF (`X-LabMITM-CSRF`); `GET /v1/session` returns the cookie CSRF secret for reload recovery. Unauthenticated `GET /v1/flows` is 401. UI-001 embeds the React flow-inspector (`internal/web` `go:embed` of `web/dist`; `make web-build`). Management bind refuses listen when `mode: bearer` has no usable token.

## Problem details

```json
{
  "type": "urn:labmitm:error:not-found",
  "title": "Not Found",
  "status": 404,
  "detail": "flow not found",
  "code": "not_found",
  "instance": "urn:labmitm:request:01J…"
}
```

`type` is `urn:labmitm:error:` plus the domain code with underscores turned to hyphens. `code` **is** the table token.

| Code | HTTP | Notes |
|---|---|---|
| `validation_failed` | 400 | |
| `unauthenticated` | 401 | |
| `forbidden` | 403 | |
| `target_denied` | 403 | data-plane + management |
| `not_found` | 404 | |
| `method_not_allowed` | 405 | |
| `revision_conflict` | 409 | |
| `idempotency_conflict` | 409 | |
| `store_full` | 409 | management insert APIs; proxy still forwards |
| `store_over_new_cap` | 400 | |
| `cursor_stale` | 400 | |
| `breakpoint_inactive` | 409 | resume/drop on a non-paused flow |
| `rate_limited` | 429 | |
| `timeout` | 504 | |
| `internal_error` | 500 | |

## Auth and origin

- `Authorization: Bearer <token>`. Health live/ready skip auth.
- `X-Forwarded-For` is not trusted.
- No CORS headers. OPTIONS is not a success path.
- Origin: present non-loopback Origin is rejected unless on `originAllowlist`. **Missing Origin is allowed** (official SDK, curl, MCPJungle). Loopback Origins (`localhost`, `127.0.0.1`, `::1`) are allowed. Published LAN UI must list the origin.
- Session cookie `labmitm_session`: `HttpOnly`, `SameSite=Lax`, `Secure` iff management TLS. CSRF header required on cookie-authenticated mutations even over HTTP. Session JSON `Cache-Control: no-store`. TTL 12h, idle 4h. **Max concurrent sessions: 64**. Cookie is REST-only.
- No `.well-known/oauth-protected-resource`.
- No HTTP Basic.

## Flow list

`GET /v1/flows?host=&method=&status=&scheme=&intercepted=&ruleId=&cursor=&limit=`

Default `limit=50`, max `200`. Sort: `StartedAt` descending, then id desc.

Cursor: opaque `base64url(id || uint64 storeGeneration || HMAC-SHA256)`. MAC key is 32 random bytes at process start, never persisted. Reset/restart kills cursors. Generation mismatch → `400` `cursor_stale`.

List items omit bodies (`requestBytes`, `responseBytes`, `truncated` flags only). List items omit the WebSocket `frames` array (`frameCount` + `truncated` only). GET-by-id frame `payload` is `string(payload)` like HTTP bodies (not base64). GET-by-id frame `action` is `drop` / `block` when a websocket-phase rule omitted or closed the frame; forwarded frames omit `action`. List items omit `grpc.messages` (`contentType` / `truncated` / `decodeError` remain). GET-by-id field `text` is a JSON string; there is no stored hex copy.

`GET /v1/flows/{id}/request` and `GET /v1/flows/{id}/response` return the captured bytes as `application/octet-stream` with `Content-Disposition: attachment` and `Content-Security-Policy: default-src 'none'`. They never reflect the captured `Content-Type` (a browser GET of `text/html` would execute scripts on the management origin).

`POST /v1/flows:wait` filter `{host, method, pathPrefix, status, after, intercepted}` + `timeout` (default 10s, cap `store.maxWait`).

## Session (REST_ONLY)

```
POST   /v1/session     Authorization: Bearer
                       Set-Cookie: labmitm_session=<opaque>; HttpOnly; SameSite=Lax; Path=/
                                   Secure iff management TLS
                       Body: { "csrf": "<32-byte hex>", "expiresAt": "…" }
GET    /v1/session     cookie or bearer → { "id", "role", "scopes", "csrf", "expiresAt" }
DELETE /v1/session     clears cookie
```

Cookie mutations (any non-GET with `Cookie: labmitm_session=…` and no `Authorization`) require header `X-LabMITM-CSRF: <csrf>`. Mismatch → `403` `forbidden`.

## Events SSE (PARITY_DIFFERENT_BINDING)

`GET /v1/events/stream` (`Accept: text/event-stream`, scope `mitm.read`):

```
event: flow.inserted
data: {"id":"01J…","host":"app.lab","storeGeneration":19}

event: flow.paused
data: {"id":"01J…","storeGeneration":20}

event: flow.deleted
data: {"id":"01J…","storeGeneration":21}

event: store.wiped
data: {"storeGeneration":22}
```

Heartbeat comment every 15s. MCP `subscriptions/listen` on `labmitm://flows` notifies **URI only**; clients pull bodies with `mitm_flows_list`.

## CA

`GET /v1/ca` returns `application/x-pem-file` (cert only, never key). Scope `mitm.read`. Not served on the unauthenticated data plane.

`GET /v1/status` includes `ca.mode`, `ca.spkiSha256`, `ca.subject`, `ca.notAfter`.

## Feature catalog

`GET /v1/features` (`mitm.read`) returns the derived hop/protocol catalog for the active snapshot:

```json
{
  "runtimeRevision": "sha256:…",
  "generation": 4,
  "drifted": true,
  "items": [
    {
      "id": "protocols.websocket",
      "yamlPath": "spec.protocols.websocket.enabled",
      "title": "WebSocket upgrade",
      "description": "…",
      "enabled": true,
      "applyMode": "live",
      "verb": "setFeature"
    }
  ]
}
```

Eleven frozen rows. Compact `status.features` booleans stay on `GET /v1/status` (including additive `httpAuth` from `spec.proxy.httpAuth.enabled`; [ADR 0017](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0017-http-proxy-407.md) K10 reopen) and are **not** nested as `features.catalog`. Mutation is `POST /v1/changes:plan` / `:apply` (`setFeature` / `replaceTLS` / `replaceHTTPAuth` / Reset), not a dedicated features write verb. `setFeature` of `proxy.httpAuth` is `validation_failed`.

Unauthenticated `GET /v1/features` is 401.

## Config plan/apply

See [docs/06-state-and-configuration.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/06-state-and-configuration.md). `:plan` is dry-run. `:apply` requires `expectedRevision`. Eighth apply verb `replaceHTTPAuth` carries `spec.proxy.httpAuth` (D76). No new `/v1` path. Catalog stays 31.

## Embedded operator UI

Required for GA / 1.0 (D13). Talks REST only.

| Item | Choice |
|---|---|
| Stack | React + TypeScript + Vite (Node 22.14.0), LabMail/TacLab pattern |
| Embed | `internal/web` `go:embed` of `web/dist` |
| Auth | Login page: paste bearer. `POST /v1/session`. Cookie + CSRF. No Basic form. |
| Pages | Flows split-pane (list stays mounted; `/` + `/flows/:id` selection drives Request / Response / TLS). Intercept vs tunnel-not-decrypt chips. Completed raw CONNECT is a tunnel summary, not empty HTTP panes. Header **:443 intercept only** is overlay/default chrome copy. Status / Audit / Reset / Login page bodies share that dark lab chrome; tunnel-not-decrypt remains a flow chip only. CA download, status (11-row feature catalog from `GET /v1/features`; `mitm.admin` live `setFeature` except `ui.enabled`; reset-only rows link to `/reset`; no `/features` route), audit (if scoped), gated reset |
| Live update | `EventSource` `GET /v1/events/stream` (`flow.inserted` / `flow.paused` / `flow.deleted` / `store.wiped`) stays mounted while selecting flows. Fallback: 3s poll of `GET /v1/flows` |
| Bodies | Render as text if `Content-Type` is text/*, json, xml, form; otherwise hex/size + download. Never `innerHTML` of response HTML. Download links use `download=` plus a blob fetch (click is not a document navigation). Raw body GETs are `application/octet-stream` + `Content-Disposition: attachment`. Optional iframe preview **only** with `sandbox` (no scripts, no same-origin) and CSP `default-src 'none'` — default **off**. |
| Missing on purpose | Fuzzer, repeater-as-weapon, payload generator, “exploit”, SSL-strip toggle |

`spec.ui.enabled: false` serves 404 for `/` but keeps REST/MCP.

## LabMITM compat flow REST (mitmproxy-inspired subset)

Opt-in, default-off, live `setFeature` / `replaceCompat` (`spec.compat.flowREST`). Extra spellings of existing `flows.*` IDs under a live prefix (default `/compat`). Disposition `REST_ONLY_PROTOCOL`: not on `catalog()`, no new MCP tools, matched after authenticate/authorize. Native `/v1/flows` stays the paginated API.

List is a JSON **array** of the newest 200; `X-LabMITM-Truncated: true` when more exist. Disabled prefix is `404` `not_found` (SPA cannot swallow it). Same bearer; `Authorization: Basic` is 401 Bearer; cookie mutations require CSRF. Not mitmproxy 11 compatible.

Contract: [examples/compat/flow-rest-contract.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compat/flow-rest-contract.md).

## Compatibility promise

`/v1/*` is versioned; breaking change requires `/v2` or a documented flag day.
