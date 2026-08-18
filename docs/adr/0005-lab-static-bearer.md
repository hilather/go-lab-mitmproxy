# ADR 0005: Lab static bearer

Status: Accepted
Date: 2026-08-18
Decisions: D6

## Context

The family uses lab static bearer tokens (TacLab ADR 0010, LabDNS, LabMail). mitmweb uses `web_password` as bearer/token query. OAuth PRM is a family exemption.

## Decision

Lab static bearer is primary. Optional HTTP Basic maps onto the same principal (`bearer_and_basic`). MCP is bearer-only. No `.well-known/oauth-protected-resource`. Default image YAML is `bearer` (not `dev-loopback-unauth`). Compat accepts `?token=` as bearer.

## Consequences

- One verifier, one scope matrix.
- MCPJungle uses `LABMITM_TOKEN`.

## Alternatives considered

- OAuth PRM: family exemption; rejected for 1.0.
- mitmweb argon2 password as the only authenticator: rejected; we still support it as the token file contents, not a second policy engine.
