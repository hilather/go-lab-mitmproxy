# Rewrite and Breakpoint Rules

Status: Proposed normative behavior
Owners: Rules, Proxy, Application
Last reviewed: 2026-08-18 (FND-001)
Related ADRs: 0002

Package `internal/rules`. Compiled into the snapshot. **Default-off.** Master switch `spec.rules.enabled` must be `true` for any item to fire. First **enabled** item whose match succeeds wins. No weights, no hash-v1, no random (D12).

## Schema

```yaml
rules:
  enabled: false
  items:
    - id: break-login          # required, unique, [a-z0-9-]{1,64}
      enabled: true
      phase: request           # request | response
      match:
        host: "app.lab.test"   # exact, or "*.lab.test"
        pathPrefix: "/login"
        pathExact: ""
        method: POST           # empty = any
        headerName: ""
        headerContains: ""
      action:
        type: delay            # breakpoint | drop | delay | status | header | body
        delay: 2s              # 0–30s
        status: 0              # status action: 400–599
        headers:
          set: {}
          remove: []
        body:
          replace: ""          # raw bytes as UTF-8 string in YAML; max 64KiB in spec
        breakpoint:
          timeout: 30s         # 1s–60s
```

Match fields are AND. Empty match matches everything (still requires `rules.enabled` and item `enabled`). Host match is case-insensitive. Path match is on the decoded URL path (no query).

| Action | Request phase | Response phase |
|---|---|---|
| `drop` | Close after optional status (default 403); no upstream | Close after sending nothing more; **illegal in 1.0 if bytes already flushed**. If response headers not yet sent, send `status` or 502. |
| `delay` | Sleep then continue | Sleep then continue |
| `status` | Do not dial; synthesize response with `status` + optional headers/body | Replace status line; headers/body as specified |
| `header` | Mutate request headers before dial | Mutate response headers before client write |
| `body` | Replace request body (fails closed if truncated / over 64 KiB spec) | Replace response body (same) |
| `breakpoint` | Pause before dial; operator resume/edit/drop | Pause after upstream, before client body |

Validate: `rules.items[].id` unique. `action.delay` ∈ [0, 30s]. `action.status` empty or 400–599. Body replace ≤ 64 KiB in YAML.

## Breakpoint flow

1. `Insert` the flow with `State=paused`, `PausedPhase=request|response` (or `Pause(id)`).
2. Store `Subscribe` emits `paused`; REST SSE and MCP `subscriptions/listen` adapt that hook.
3. Proxy session `WaitPaused(ctx, id)` with ctx deadline = rule timeout (1s–60s, cap `store.maxWait`).
4. `POST /v1/flows/{id}:resume` → `store.Resume` (optional header/body patch, same caps).
5. `POST /v1/flows/{id}:drop` → `store.Drop` (client gets 502 if headers not sent).
6. Timeout / `ErrStaleEpoch` → continue unmodified (do not hang the SUT). Audit `flow.breakpoint_timeout`.

PR 6 unit test: `Insert` paused → goroutine `WaitPaused` → `Resume` with patch → assert patch and `State=completed` path without opening a socket. Compile of YAML → rule index is PR 7 only; PR 6 uses a test-constructed snapshot.

## Replay

Replay is **not** a rule action. `POST /v1/flows/{id}:replay` calls `proxy.Replay(stored *Flow)`:

- Builds origin-form from the stored request (`scheme`, `host`, `method`, `path`, headers, body).
- Dials the **origin** via the same resolve-then-guard + `DialContext` path as live traffic.
- If `scheme=https`, `tls.Client` on that dial using the current snapshot’s upstream verify knobs. Does **not** require `tls.intercept` to be on — replay is an operator-originated origin fetch, not a client CONNECT.
- `Transport.Proxy = nil`. `HTTP_PROXY=http://127.0.0.1:8888` must not change the dial.
- Never dial `listeners.proxy.address` (hairpin reject even if that address is loopback).
- New flow id. Requires `mitm.write`.
- Reject `Protocol=websocket|connect`, CONNECT-metadata-only flows, and flows with `Request.Truncated` (`validation_failed`).

Tests: HTTP replay; HTTPS replay with intercept both on and off; `HTTP_PROXY` ignored; hairpin address rejected.

Live apply `replaceRules` compiles a new snapshot; in-flight requests keep the old snapshot.

## Related documents

- Stream vs mutate: [docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md)
- Store breakpoint primitives: [docs/04-flow-store.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/04-flow-store.md)
- Plan/apply `replaceRules`: [docs/06-state-and-configuration.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/06-state-and-configuration.md)
