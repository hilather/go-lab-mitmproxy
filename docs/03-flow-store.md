# Flow Store

Status: Proposed normative behavior
Owners: Store, Proxy, Control Plane
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0003

Captured flows are runtime evidence, not desired state. Restart or `state.reset` wipes them. Config revision is independent of `storeGeneration`.

## Identity

- Flow ids are Crockford ULIDs (`github.com/oklog/ulid/v2`), URL-safe, monotonic.
- mitmweb compat may present the same id as hex-with-dashes **only if** we also accept ULID on native `/v1`. **Frozen:** native ids are ULIDs. Compat `/flows/{id}` accepts ULID. If a client sends UUID form, 404. Do not dual-key.

## Caps (stacked)

| Knob | Default | Meaning |
|---|---|---|
| `store.maxFlows` | 10000 | Count cap |
| `store.maxBytes` | 512MiB | Resident raw request+response+WS payloads |
| `store.maxInFlight` | 256 | Flows not yet complete |
| `store.fullPolicy` | `evict_oldest` | `reject` refuses new flows (proxy 502 `store_full`) or `evict_oldest` |
| `store.spillDirectory` | `""` | Empty = memory only. Non-empty must be under tmpfs `/tmp/labmitm-spill` |
| `store.spillThreshold` | 1MiB | Bodies larger than this may spill |
| `store.maxWait` | 60s | Cap for `flows.wait` |

`resident + in-flight ≤ maxBytes`. Exceeding with `reject` → new flow error, client 502, metric `labmitm_store_full_total`.

Mark, comment, and intercept-resume do **not** bump `storeGeneration`. Insert, delete, clear, evict, wipe, and content replacement do.

## Intercept

When `spec.proxy.intercept.active` and the filter matches:

1. The flow is stored with `Intercepted=true`.
2. The client/upstream is **not** forwarded until `flows.resume` (or kill).
3. Operators may `flows.update` request/response before resume.
4. Bulk `flows.resume` / `flows.kill` apply to all intercepted (filter optional).

Kill: close both sides; flow remains with error `killed`.

## Replay

### Client replay

Re-issue the captured request through the current proxy snapshot (host, TLS, addons). Creates a **new** flow marked `Replay=client` linked via `metadata.replayOf`. Concurrency: `client_replay_concurrency` `1` or `-1`.

### Server replay

Match inbound requests to stored responses. Matching knobs (mitmproxy names):

- `server_replay_ignore_content`
- `server_replay_ignore_host`
- `server_replay_ignore_port`
- `server_replay_ignore_params`
- `server_replay_ignore_payload_params`
- `server_replay_use_headers`
- `server_replay_reuse` (nopop)
- `server_replay_refresh` (date/expires/last-modified/cookie)
- `server_replay_extra`: `forward` / `kill` / numeric status

Offline: `connection_strategy=lazy`.

## Export / import

| Format | 1.0 | Notes |
|---|---|---|
| HAR 1.2 | required | `GET /v1/flows:har`, MCP `mitm_flows_har_export` |
| LabMITM JSONL `labmitm-dump-v1` | required | One flow per line, canonical field order |
| mitmproxy flow dump | not written | Optional 1.1 reader only |

`GET /v1/flows:dump` returns JSONL. Compat `GET /flows/dump` returns JSONL with `Content-Disposition: attachment` (not Python bytes). Document the difference in [docs/12-mitmweb-compat.md](12-mitmweb-compat.md). `POST` dump imports JSONL or HAR (`Content-Type`).

## Wait

`POST /v1/flows:wait` / `mitm_flows_wait`:

```json
{
  "filter": "~u login",
  "timeout": "10s"
}
```

Returns the first matching **completed** flow (or intercepted, if `includeIntercepted: true`) or `timeout`. Does not delete. Agent replacement for poll loops.

## Content views

Server-side views, cap `content_view_lines_cutoff` default 512:

`auto`, `raw`, `hex`, `json`, `urlencoded`, `multipart`, `xml`, `javascript`, `css`, `image-meta` (no pixel decode into logs), `websocket`.

Unknown view → `validation_failed`. Views never execute HTML/JS.

## Related documents

- Config store section: [docs/04-state-and-configuration.md](04-state-and-configuration.md)
- REST: [docs/06-rest-api.md](06-rest-api.md)
