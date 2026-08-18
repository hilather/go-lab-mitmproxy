# Filter Language

Status: Proposed normative behavior
Owners: Filters, Proxy
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0002

LabMITM implements mitmproxy-compatible filter expressions using Go RE2 (`regexp`). Python-regex features that RE2 cannot express fail parse with `validation_failed`.

## Operators (1.0)

| Token | Meaning |
|---|---|
| `~a` | Asset response (css, js, image, font content-type) |
| `~all` | All flows |
| `~b regex` | Any body |
| `~bq regex` | Request body |
| `~bs regex` | Response body |
| `~c int` | HTTP status |
| `~comment regex` | Comment |
| `~d regex` | Domain / host |
| `~dns` | DNS flows (no-op match none in 1.0 unless H3/DNS later) |
| `~dst regex` | Destination address |
| `~e` | Error |
| `~h regex` | Any header `name: value` |
| `~hq regex` | Request header |
| `~hs regex` | Response header |
| `~http` | HTTP flows |
| `~m regex` | Method |
| `~marked` | Marked |
| `~marker regex` | Marker text |
| `~meta regex` | Metadata string |
| `~q` | Request without response |
| `~replay` | Replayed |
| `~replayq` | Client replay |
| `~replays` | Server replay |
| `~s` | Has response |
| `~src regex` | Source address |
| `~t regex` | Content-Type |
| `~tcp` | TCP flows (none in 1.0 default) |
| `~tq` / `~ts` | Request/response Content-Type |
| `~u regex` | URL |
| `~udp` | UDP (none in 1.0) |
| `~websocket` | WebSocket |
| `!` `&` `\|` `()` | Boolean |

Bare strings match URL (`~u`). Default combiner `&`. Regexes case-insensitive unless `LABMITM_CASE_SENSITIVE_FILTERS=1`.

## View selectors (interactive / commands)

`@all` `@focus` `@shown` `@hidden` `@marked` `@unmarked`

`@focus` in MCP/REST is the optional `focusId` parameter; if omitted, `@focus` is invalid (`validation_failed`).

## Tests

FILT-001 ships a table in `testdata/filter/cases.json` covering every operator above with at least one positive and one negative fixture. Integration tests parse filters used by intercept and `flows.list`.
