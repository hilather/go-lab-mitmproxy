# ADR 0012: CA is a secret, not runtime state

Status: Accepted
Date: 2026-08-18
Decisions: D10

## Context

mitmproxy generates `~/.mitmproxy/mitmproxy-ca.pem` on first start. In the lab, restart must not mint a new CA (clients and secrets would desync). Flow wipe must not rotate keys.

## Decision

CA files live on a read-only secret mount (`spec.tls.confDir`). `serve` fail-closes if missing. `labmitm ca generate` and `mcplab secrets` create them. Reset does not rewrite the CA. Key export default-off.

## Consequences

- First lab boot must mint secrets before `serve` is ready.
- Operators can reuse a mitmproxy CA filename alias.

## Alternatives considered

- Generate CA on every start into tmpfs: breaks trust; rejected.
- Generate once into a writable volume: second source of truth; rejected in favor of `mcplab secrets`.
