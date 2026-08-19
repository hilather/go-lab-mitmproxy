# ADR 0006: Pin supported MCP protocol versions

Status: Accepted
Date: 2026-08-18
Decisions: D14, D15

## Context

MCP evolves and recent revisions changed transport and statelessness behavior. Claiming support for an unpinned latest version would make compatibility and testing ambiguous.

LabDNS hard-pins `2026-07-28` with no compatibility knob; `mcp-integration-lab` carries `patches/go-lab-dns-wire-mcp.patch` because MCPJungle (`mark3labs/mcp-go v0.48`) cannot speak that pin. TacLab / LabMail ship `allowLegacyClients` (default false; lab turns it on). LabMITM is a new appliance and should not require a lab patch. Family docs cite `mark3labs/mcp-go v0.48` as the reason the knob exists; that pin was **not** re-measured against the current MCPJungle image.

## Decision

**D14 — Go 1.26, official MCP SDK `v1.7.0`, protocol `2026-07-28`, Apache-2.0.**

- Record the pin in `internal/buildinfo` and `/v1/version`.
- Transport: Streamable HTTP `POST /mcp`, `Stateless: true`.
- Add a protocol version only after conformance and parity tests pass.

**D15 — `spec.management.mcp.allowLegacyClients` default false; integration-lab overlay sets true.**

- TacLab / LabMail-shaped knob so MCPJungle can register without a LabMITM patch.
- `subscriptions/listen` stays pinned to 2026-07-28 even when the pin is relaxed.
- Missing Origin is allowed (same as REST).
- Do not copy LabDNS’s lab patch.

## Consequences

- Behavior is reproducible.
- Protocol upgrades are explicit reviewed work.
- The lab bootstrap YAML must set `allowLegacyClients: true`.
- Release notes must list MCP version changes.

## Alternatives considered

- Track SDK main automatically: rejected due to nondeterminism.
- Custom MCP implementation: rejected unless the official SDK cannot satisfy required behavior and an ADR replaces this one.
- Hard pin with no knob (LabDNS): would require a lab patch. Rejected for LabMITM.
- Default `allowLegacyClients: true`: too loose for standalone / hardened deploys. Lab overlay turns it on.

## Review triggers

Review this decision when MCPJungle speaks 2026-07-28 natively, when the official SDK cannot satisfy required behavior, or when a new protocol version is proposed.
