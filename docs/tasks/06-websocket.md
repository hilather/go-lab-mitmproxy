# WS-001: WebSockets

Status: not-started
Recommended owner: WebSocket agent
Dependencies: PROXY-001, STORE-001
Exclusive ownership: `internal/proxy/ws`
Wave: 4

## Goal

Capture WebSocket upgrade and messages; support intercept/kill; optional per-message intercept as specified in docs/02.

## Design references

- [ ] `docs/02-proxy-semantics.md` WebSocket
- [ ] `docs/03-flow-store.md`

## Scope

- [ ] HTTP/1 Upgrade handling without leaking hop-by-hop incorrectly.
- [ ] Message frames stored on the flow.
- [ ] `websocket: false` rejects upgrade.
- [ ] Kill closes both sides.

## Required tests

- [ ] **Integration:** local WS client/server through proxy, echo message captured.
- [ ] Kill while connected.
- [ ] Filter `~websocket` (needs FILT-001; skip with build tag only if FILT not merged — prefer depend and use filter package).

If FILT-001 is not merged, depend on it or duplicate a tiny `~websocket` check — **prefer wait/rebase on FILT-001**.

## Acceptance criteria

- WS echo fixture green in CI.
