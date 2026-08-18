# mitmweb Compatibility Adapter

Status: Proposed normative behavior
Owners: REST, Compat
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0008

mitmweb’s Tornado routes are a **compat adapter** (`REST_ONLY_PROTOCOL`). They call `app.Service` only. Native agents must use `/v1` and MCP.

Enabled when `spec.listeners.management.compatEnabled` is true (default true).

## Route map

| mitmweb | Native capability | Notes |
|---|---|---|
| `GET /flows` | `flows.list` | JSON array or `{flows:[…]}` — freeze array-of-flow objects matching documented fields we independently define; do not copy Python `flow_to_json` source. Include `id`, `request`, `response`, `error`, `intercepted`, `marked`, `timestamp_start`. |
| `PUT /flows/{id}` | `flows.update` | |
| `DELETE /flows/{id}` | `flows.delete` | |
| `POST /flows/{id}/resume` | `flows.resume` | |
| `POST /flows/{id}/kill` | `flows.kill` | |
| `POST /flows/{id}/duplicate` | `flows.duplicate` | |
| `POST /flows/{id}/replay` | `flows.replay_client` | |
| `POST /flows/{id}/revert` | `flows.revert` | |
| `POST /flows/resume` | `flows.resume_all` | |
| `POST /flows/kill` | `flows.kill_all` | |
| `GET /flows/dump` | `flows.dump_export` | **JSONL**, not mitmproxy binary. Header `X-LabMITM-Dump: labmitm-dump-v1` |
| `POST /flows/dump` | `flows.dump_import` | |
| `GET/POST …/content.data` | `flows.content_get` / `set` | |
| `GET …/content/{view}` | `flows.content_view` | |
| `POST /clear` | `flows.clear` | |
| `GET /options` | `state.get` redacted + intercept | Not a writable confdir |
| `PUT /options` | `changes.plan`+`apply` subset | Unknown mitmproxy-only options → 400 |
| `POST /options/save` | — | **403** `forbidden` (`options_save_disabled`) |
| `GET /state` | `status.get` | |
| `GET /commands` | `commands.list` | |
| `POST /commands/{cmd}` | `commands.execute` | |
| `GET /events` | `events.list` | |
| `GET /filter-help` | `filter.help` | |
| `GET /updates` WebSocket | `events.stream` | Frame JSON events; independent schema |
| `GET /processes` | — | **404** in 1.0 (local mode deferred) |
| `GET /executable-icon` | — | 404 |
| `GET /` | SPA | LabMITM UI, not mitmweb assets |

Auth: same as `/v1` (bearer; optional basic). mitmweb `token` query param is accepted as bearer equivalent (compat only).

## Explicit differences (not bugs)

1. Dump format is JSONL/HAR, not Python flow dump.
2. Flow ids are ULIDs, not UUID hex.
3. `/options/save` never writes disk.
4. No `/processes`.
5. WebSocket `/updates` event names use `flow.created` etc., documented in a golden.

`TestMitmwebScenarioCompat` (SEC-001): unauthenticated `GET /flows` → 401; bearer/basic → list; curl via proxy creates a flow that appears in `/flows`.
