# REST API

Status: Proposed normative behavior
Owners: REST, Application
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0004, 0005, 0008

Base: `/v1`. JSON unless noted. Errors: `Content-Type: application/problem+json`. Capability table: [docs/05-control-plane-and-parity.md](05-control-plane-and-parity.md). Generated OpenAPI: `api/openapi/v1.json` (after API-001). `labmitm serve` binds this listener from YAML `spec.listeners.management.address` (default `:8081`); `--management-listen ADDR|off` overrides.

When `spec.ui.enabled` is true (default), unmatched non-API GET/HEAD paths serve the embedded SPA. `/v1`, `/mcp`, mitmweb compat mounts, `/healthz`, and `/.well-known` stay problem+json.

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

`application/problem+json` `code` **is** the table token. `type` is `urn:labmitm:error:` plus that token with underscores turned to hyphens.

| Code | HTTP |
|---|---|
| `validation_failed` | 400 |
| `unauthenticated` | 401 |
| `forbidden` | 403 |
| `not_found` | 404 |
| `method_not_allowed` | 405 |
| `revision_conflict` | 409 |
| `idempotency_conflict` | 409 |
| `store_full` | 409 |
| `intercept_inactive` | 409 |
| `cursor_stale` | 400 |
| `rate_limited` | 429 |
| `timeout` | 504 |
| `unsupported_capability` | 501 |
| `internal_error` | 500 |

See [docs/17-error-model.md](17-error-model.md).

## Auth and origin

Auth: `Authorization: Bearer <token>` or (when `bearer_and_basic`) `Authorization: Basic …`. Health live/ready skip auth. `X-Forwarded-For` is not trusted. No CORS headers. Loopback unauthenticated only when `mode: dev-loopback-unauth` (not the container default).

**Origin:** a **present** non-loopback `Origin` is rejected unless it is on `originAllowlist`. **Missing Origin is allowed** (official SDK, curl, MCPJungle). Loopback Origins are `localhost`, `127.0.0.1`, `::1`.

Mutations accept `Idempotency-Key` and `If-Match` / body `expectedRevision` or `expectedStoreGeneration`. Idempotency LRU default 256; reset clears it.

## Health

| Probe | Meaning | Auth |
|---|---|---|
| `GET /v1/health/live` | Process up | none |
| `GET /v1/health/ready` | Proxy bound **and** CA loaded **and** store initialized **and** (management bound or explicitly off) | none |

Ready becomes unready as soon as proxy `Shutdown` begins.

## Flow list

`GET /v1/flows?filter=&cursor=&limit=&order=time|method|url|size&reversed=`

Default `limit=50`, max `200`. Cursor: opaque `base64url(id || uint64 storeGeneration || HMAC-SHA256)` with process-start MAC key (LabMail rule). Generation mismatch → `cursor_stale`.

List items omit raw bodies (`hasContent` bools only). Full `GET /v1/flows/{id}` includes headers and metadata; bodies via content endpoints.

## Wait

`POST /v1/flows:wait` — see [docs/03-flow-store.md](03-flow-store.md).

## Session (REST_ONLY)

Cookie name **`labmitm_session`**. CSRF header `X-LabMITM-CSRF`. Same semantics as LabMail (`POST/GET/DELETE /v1/session`). Cookie is REST-only; MCP never sees it.

## Events SSE

`GET /v1/events/stream`:

```
event: flow.created
data: {"id":"01J…","url":"https://…","storeGeneration":19}

event: flow.updated
data: {"id":"01J…","intercepted":true}

event: flow.deleted
data: {"id":"01J…","storeGeneration":20}

event: store.wiped
data: {"storeGeneration":21}
```

Heartbeat comment every 15s.

## Compatibility promise

`/v1/*` is versioned; breaking change requires `/v2` or a documented flag day. mitmweb compat is not the native contract.
