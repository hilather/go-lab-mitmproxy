# LabMITM compat flow REST (mitmproxy-inspired subset)

Status: Lab-facing contract (1.1, opt-in)
Last reviewed: 2026-08-28

This is **not** mitmproxy 11 compatible. There is no mitmweb, dumpfile, CLI flag
clone, addon VM, HTTP Basic, PUT mutate, UUID ids, or filter DSL. IDs are
ULIDs. Auth is the same lab static bearer as native `/v1`. Enable is live
`setFeature` (`compat.flowREST`) or `replaceCompat` (enabled and `pathPrefix`).
Default prefix is `/compat`.

See [ADR 0011](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0011-optional-compat-flow-rest.md)
and [docs/07](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/07-control-plane-and-parity.md).
Goldens: [testdata/compat](https://github.com/hilather/go-lab-mitmproxy/blob/main/testdata/compat).

## Enable

```yaml
spec:
  compat:
    flowREST:
      enabled: true
      pathPrefix: /compat
```

When `enabled` is false (1.0 default), the live prefix returns
`404` `not_found` `application/problem+json`. The SPA does not swallow it.

## Surface

| Method | Path | Native | Notes |
|---|---|---|---|
| `GET` | `{prefix}/flows` | `GET /v1/flows` | JSON **array**, newest 200. `X-LabMITM-Truncated: true` if more. |
| `GET` | `{prefix}/flows/{id}` | `GET /v1/flows/{id}` | Mapped object. |
| `DELETE` | `{prefix}/flows/{id}` | `DELETE /v1/flows/{id}` | `204`. CSRF if cookie. |
| `DELETE` | `{prefix}/flows` | `DELETE /v1/flows` | `204`. CSRF if cookie. |
| `POST` | `{prefix}/flows/{id}/replay` | `POST /v1/flows/{id}:replay` | Mapped **new** flow. CSRF if cookie. |
| `GET` | `{prefix}/flows/{id}/content/request` | `GET /v1/flows/{id}/request` | `application/octet-stream` + CSP. |
| `GET` | `{prefix}/flows/{id}/content/response` | `GET /v1/flows/{id}/response` | same. |

`Authorization: Basic` is `401` with `WWW-Authenticate: Bearer realm="labmitm"`.

## Mapped object

```json
{
  "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "intercepted": true,
  "type": "http",
  "error": null,
  "request": {
    "method": "GET",
    "scheme": "https",
    "host": "app.lab",
    "port": 443,
    "path": "/login",
    "http_version": "HTTP/2.0",
    "headers": [[":method", "GET"], [":authority", "app.lab"], ["user-agent", "curl"]],
    "contentLength": 0,
    "timestamp_start": 1787155200.123
  },
  "response": {
    "status_code": 200,
    "reason": "OK",
    "http_version": "HTTP/2.0",
    "headers": [["content-type", "text/plain"]],
    "contentLength": 2,
    "timestamp_end": 1787155200.200
  }
}
```
