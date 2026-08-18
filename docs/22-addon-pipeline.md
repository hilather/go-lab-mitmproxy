# Addon Pipeline

Status: Proposed normative behavior
Owners: Proxy, Addons
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0007

mitmproxy’s power is the addon event pipeline. LabMITM 1.0 implements the same **idea** with in-tree Go addons plus Starlark. Python `.py` scripts are rejected at validate.

## Hook order (frozen)

Hooks run in this order for each HTTP exchange. Built-ins and Starlark share the list. A hook may set `flow.Error` and stop.

1. `client_connected`
2. `requestheaders`
3. `request` (body complete, unless streamed)
4. `server_connect` / `server_connected` (may be skipped if map_local, block, or server replay)
5. `responseheaders`
6. `response`
7. `error` (on failure)
8. `client_disconnected` / `server_disconnected`

WebSocket: `websocket_start`, `websocket_message`, `websocket_end`.

Starlark may register a subset. Unimplemented hook names in a script are errors at load.

## Built-in addons (1.0)

| Addon | mitmproxy option | Behavior |
|---|---|---|
| anticache | `anticache` | Strip request headers that invite 304 |
| anticomp | `anticomp` | Ask for identity encoding |
| block_list | `block_list` | Filter + status (444 closes) |
| map_local | `map_local` | Regex URL → file under allowDir |
| map_remote | `map_remote` | URL rewrite |
| modify_headers | `modify_headers` | Pattern `[/filter]/name/value` |
| modify_body | `modify_body` | Regex replace; `@file` under allowDir |
| intercept | `intercept` + `intercept_active` | Hold matching flows |
| stickyauth | `stickyauth` | Replay Authorization from first match |
| stickycookie | `stickycookie` | Replay Cookie |
| serverplayback | `server_replay*` | [docs/03-flow-store.md](03-flow-store.md) |
| clientplayback | `client_replay*` | |
| proxyauth | `proxyauth` | Data-plane auth |
| tlsconfig | TLS spec | |
| update_alt_svc | reverse | Strip Alt-Svc unless keep |
| strip_dns_https | `strip_ech` | If DNS mode later; 1.0 no-op unless HTTPS RR seen in DNS mode (out of 1.0) |
| onboarding | `onboarding` | mitm.it |
| dumper | CLI only | slog at debug |

Not in 1.0: `browser`, `asgiapp`, `command_history` file persist, `next_layer` Python layer chooser (Go owns layer choice).

## Starlark surface (1.0)

Scripts receive a frozen-ish `flow` module:

- Read: `flow.id`, `flow.request.method`, `.url`, `.host`, `.path`, `.headers.get`, `.content` (bytes, capped)
- Write (before resume / before forward): `flow.request.headers.set`, `.content =`, `flow.response = struct(...)` to short-circuit
- `log.info(msg)`
- No `import`, no file I/O, no net. `time.sleep` forbidden; use intercept instead.

CPU/time budget: 10ms default per hook, configurable cap 100ms. Exceed → `script.failed`, flow continues unless `failClosed: true` on the script spec.

`scripts:` entries are paths under `spec.addons.scriptAllowDir` (default `/etc/labmitm/scripts`).

## Related documents

- Config: [docs/04-state-and-configuration.md](04-state-and-configuration.md)
- Filters: [docs/24-filter-language.md](24-filter-language.md)
