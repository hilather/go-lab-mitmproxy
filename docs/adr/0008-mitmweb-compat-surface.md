# ADR 0008: mitmweb compatibility surface

Status: Accepted
Date: 2026-08-18
Decisions: D5

## Context

mitmweb exposes a Tornado REST/WebSocket API. Lab operators may have scripts against `/flows`. Native family APIs are `/v1` + MCP.

## Decision

mitmweb routes are a compat adapter (`REST_ONLY_PROTOCOL`) calling `app.Service`. Native `/v1` and MCP are the contract. Dump bytes are JSONL, not Python flow dumps. `/options/save` is 403. `/processes` is 404 in 1.0.

## Consequences

- Dual HTTP mounts on the management listener.
- Compat tests must not copy Python serializers; independently specified goldens.

## Alternatives considered

- Compat-only (no `/v1`): rejected; no MCP-shaped resources and no family look.
- No compat: more churn for existing mitmweb REST users; rejected for 1.0.
