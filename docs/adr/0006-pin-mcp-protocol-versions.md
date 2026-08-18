# ADR 0006: Pin supported MCP protocol versions

Status: Accepted
Date: 2026-08-18
Decisions: D14, D15

## Context

LabDNS hard-pins `2026-07-28` and the lab carries a patch because MCPJungle speaks an older generation. TacLab/LabMail ship `allowLegacyClients` (default false; lab turns it on). LabMITM must not require a lab patch.

## Decision

- Official SDK `v1.7.0`, protocol `2026-07-28`, Streamable HTTP `POST /mcp`, `Stateless: true`.
- `spec.management.mcp.allowLegacyClients` default false; lab overlay true.
- `subscriptions/listen` stays 2026-07-28 even when the pin is relaxed.

## Consequences

- Reproducible protocol tests.
- Lab bootstrap YAML must set `allowLegacyClients: true`.

## Alternatives considered

- Track SDK main: rejected.
- Hard pin with no knob: would require a lab patch; rejected.
