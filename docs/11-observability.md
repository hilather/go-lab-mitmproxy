# Observability

Status: Proposed normative behavior
Owners: Observability, Proxy, Control Plane
Last reviewed: 2026-08-18 (FND-001)
Related ADRs: 0001

## Logs (`log/slog` JSON)

Frozen event names (`labmitm.dev/metrics/v1alpha1`; generated from `internal/observability`):

```
proxy.accepted proxy.rejected proxy.session_end
tls.intercept tls.upstream_insecure
store.inserted store.deleted store.wiped store.full
rule.hit flow.paused flow.resumed
http.request mcp.call
auth.failure auth.success
state.reset state.apply
```

Fields: `timestamp`, `level`, `event`, `component`, `request_id`, `flow_id`, `host` (only when `logLevel=debug` **or** host is a lab suffix — **closed:** never put raw Host in info logs; use `host_class=public|lab|ip|unknown` at info), `capability`, `result`, `error_code`, `duration_ms`, `store_generation`. Do **not** log bodies, `Authorization`, `Cookie`, `Set-Cookie`, or PEM keys. Remote IP only at `debug`.

## Metrics (hand-rolled OpenMetrics)

Same style as LabDNS / LabMail `internal/observability`. No `github.com/prometheus/*`. Default listen `127.0.0.1:9090` (empty disables). `publicPath: true` exposes authenticated `GET /v1/metrics`. Scrape listener is unauthenticated (bind loopback).

Bounded labels only.

| Name | Kind | Labels |
|---|---|---|
| `labmitm_proxy_sessions_total` | counter | `result` (`ok`, `rejected`, `timeout`) |
| `labmitm_proxy_rejected_total` | counter | `reason` (`admission`, `http2`, `socks`, `target_denied`, `absolute_https`) |
| `labmitm_flows_total` | counter | `scheme`, `intercepted`, `result` |
| `labmitm_tls_intercepts_total` | counter | `result` (`ok`, `mint_fail`, `tls_handshake`, `upstream_tls`, `upstream_verify_fail`, `http2_inner`) |
| `labmitm_rule_hits_total` | counter | `action` |
| `labmitm_store_flows` | gauge | — |
| `labmitm_store_bytes` | gauge | — |
| `labmitm_store_evictions_total` | counter | — |
| `labmitm_store_full_total` | counter | — |
| `labmitm_store_waiters` | gauge | — |
| `labmitm_http_requests_total` | counter | `capability`, `code_class` |
| `labmitm_http_request_duration_seconds` | histogram | `capability` |
| `labmitm_mcp_calls_total` | counter | `tool`, `result` |
| `labmitm_auth_failures_total` | counter | `reason` |
| `labmitm_audit_events_total` | counter | `event` |
| `labmitm_telemetry_dropped_total` | counter | `reason` |

## Health

| Probe | Meaning |
|---|---|
| `GET /v1/health/live` | Process up (listener goroutines not deadlocked) |
| `GET /v1/health/ready` | Proxy bound **and** (management bound or explicitly off) **and** store initialized **and** CA compiled if `intercept: true` |

Ready does **not** require MCP clients, a non-empty store, or successful upstreams.

Ready becomes unready as soon as proxy `Shutdown` begins.

Healthcheck CLI: `labmitm healthcheck --url=http://127.0.0.1:8088/v1/health/ready`.

## Alerting (operator, not shipped as SaaS)

- Ready failing for >30s
- `store_full` rate > 0 in a lab that expected capture
- `tls.upstream_insecure` after a profile that claimed verify-on
- `auth_failures` spike
