# Observability

Status: Proposed normative behavior
Owners: Observability, Proxy, Control Plane
Last reviewed: 2026-08-23 (D66 labmitm_grpc_decode_total)
Related ADRs: 0001

## Logs (`log/slog` JSON)

Frozen event names in [`api/metrics/v1alpha1.json`](https://github.com/hilather/go-lab-mitmproxy/blob/main/api/metrics/v1alpha1.json) (`labmitm.dev/metrics/v1alpha1`; generated from `internal/observability`):

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

Same exposition style as LabDNS / LabMail `internal/observability`: write OpenMetrics text; **do not** import `github.com/prometheus/*`. Go source of truth: `internal/observability`. `make generate` / `make verify-generated` keep [`api/metrics/v1alpha1.json`](https://github.com/hilather/go-lab-mitmproxy/blob/main/api/metrics/v1alpha1.json) current. `spec.observability.metrics.listen` default `127.0.0.1:9090` (empty disables). A lab overlay that needs compose scraping sets `listen: ":9090"` (or `0.0.0.0:9090`). `publicPath: true` exposes authenticated `GET /v1/metrics` on the management listener; default `false`. The scrape listener serves `/metrics` unauthenticated (bind loopback unless the overlay needs compose scraping).

Bounded labels only.

| Name | Kind | Labels |
|---|---|---|
| `labmitm_proxy_sessions_total` | counter | `result` (`ok`, `rejected`, `timeout`) |
| `labmitm_proxy_rejected_total` | counter | `reason` (`admission`, `http2`, `socks`, `socks_auth`, `socks_command`, `target_denied`, `absolute_https`, `origdest`) |
| `labmitm_socks_sessions_total` | counter | `result` (`ok`, `denied`, `auth`, `command`) |
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
| `labmitm_h2_trailer_dropped_total` | counter | — |
| `labmitm_ws_frames_total` | counter | `opcode` (`continuation`, `text`, `binary`, `close`, `ping`, `pong`, `other`) |
| `labmitm_grpc_decode_total` | counter | `result` (`ok`, `malformed`, `truncated`, `skipped`) |

## Health

| Probe | Meaning |
|---|---|
| `GET /v1/health/live` | Process up (listener goroutines not deadlocked) |
| `GET /v1/health/ready` | Proxy bound **and** (management bound or explicitly off) **and** (orig-dest bound or `OrigDestOff`) **and** store initialized **and** CA compiled if `intercept: true` |

Ready does **not** require MCP clients, a non-empty store, or successful upstreams.

Ready becomes unready as soon as proxy `Shutdown` begins.

1.0 default is `OrigDestOff: true` (orig-dest disabled). Warning `origdest_unbound` (and `listener_unbound`) fires only when original-destination is **required** and unbound. Flag-off processes stay ready.

Healthcheck CLI: `labmitm healthcheck --url=http://127.0.0.1:8088/v1/health/ready`.

There is no `labmitm_h2_streams_total` or `labmitm_origdest_sessions_total` in the 1.1 catalog. SOCKS outcomes are `labmitm_socks_sessions_total`. Orig-dest recover/deny closes increment `labmitm_proxy_rejected_total{reason="origdest"}`. Inner HTTP/2 preface while the flag is off stays `labmitm_tls_intercepts_total{result="http2_inner"}`.

## Alerting (operator, not shipped as SaaS)

- Ready failing for >30s
- `store_full` rate > 0 in a lab that expected capture
- `tls.upstream_insecure` after a profile that claimed verify-on
- `auth_failures` spike
- `origdest_unbound` when `originalDestination.enabled` is true and the listener did not bind
