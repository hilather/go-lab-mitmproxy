# Threat Model

Status: Proposed
Owners: Security
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0005, 0009, 0012

## Assets

- Captured request/response bodies (credential-adjacent lab data).
- Lab CA private key.
- Management bearer tokens.
- Ability to modify and replay traffic toward lab systems.

## Actors

- Lab operators and MCP agents (authorized).
- Systems under test (data-plane clients).
- Untrusted network clients hitting published ports.
- Malicious captured content (HTML/JS) attacking the operator browser.

## Trust boundaries

1. Data-plane proxy port vs management port.
2. Container vs host (no Docker socket, no caps).
3. CA secret mount vs flow memory.
4. Starlark sandbox vs Go runtime.
5. `map_local` allow directory vs filesystem.

## Mitigations

Mapped in [docs/08-security-architecture.md](08-security-architecture.md). Privileged capture modes are out of the 1.0 trust boundary (ADR 0009).

## Residual risk (accepted for lab)

- An operator with `mitm.admin` can intercept lab TLS and read traffic. That is the product.
- `block_global: false` in the lab overlay means any reachable client can use the forward proxy. Bind and firewall at the lab edge; document it.
- Starlark is sandboxed but not a full security hypervisor; scripts require `mitm.script`.
