# Observability

Status: Proposed normative behavior
Owners: Observability, Proxy, Control Plane
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0001

## Logs (`log/slog` JSON)

Frozen event names (generated into `api/metrics/v1alpha1.json` after OBS-001):

```
proxy.accepted proxy.rejected proxy.session_end
tls.intercept tls.passthrough tls.error
store.inserted store.deleted store.wiped store.full
flow.intercepted flow.resumed flow.killed flow.replayed
http.request mcp.call
auth.failure auth.success
state.reset state.apply
script.loaded script.failed
```

Fields: `timestamp`, `level`, `event`, `component`, `request_id`, `flow_id`, `capability`, `result`, `error_code`, `duration_ms`, `store_generation`. Do **not** log bodies, `Authorization`, cookie values, or CA keys. Hostnames only at `debug`.

## Metrics (hand-rolled OpenMetrics)

Do **not** import `github.com/prometheus/*`. Default scrape `127.0.0.1:9090`. `publicPath: true` exposes authenticated `GET /v1/metrics`.

Bounded labels only.

| Name | Kind | Labels |
|---|---|---|
| `labmitm_proxy_sessions_total` | counter | `mode`, `result` |
| `labmitm_proxy_sessions_active` | gauge | `mode` |
| `labmitm_tls_handshakes_total` | counter | `result` (`intercept`, `passthrough`, `error`) |
| `labmitm_http_exchanges_total` | counter | `http_version`, `result` |
| `labmitm_ws_messages_total` | counter | `opcode` |
| `labmitm_store_flows` | gauge | — |
| `labmitm_store_bytes` | gauge | — |
| `labmitm_store_evictions_total` | counter | — |
| `labmitm_store_full_total` | counter | — |
| `labmitm_intercept_held` | gauge | — |
| `labmitm_http_requests_total` | counter | `capability`, `code_class` |
| `labmitm_mcp_calls_total` | counter | `tool`, `result` |
| `labmitm_auth_failures_total` | counter | `reason` |
| `labmitm_audit_events_total` | counter | `event` |
| `labmitm_telemetry_dropped_total` | counter | `reason` |

## Health

| Probe | Meaning |
|---|---|
| `GET /v1/health/live` | Process up |
| `GET /v1/health/ready` | Proxy bound **and** CA loaded **and** store initialized **and** (management bound or off) |

Ready does **not** require MCP clients or a non-empty flow list.

CLI: `labmitm healthcheck --url=http://127.0.0.1:8081/v1/health/ready`.
