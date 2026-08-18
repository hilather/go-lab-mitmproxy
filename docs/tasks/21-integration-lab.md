# LAB-001: mcp-integration-lab Overlay

Status: not-started
Recommended owner: Integration agent
Dependencies: COMPAT-001, MCP-001, SEC-001, DEP-001
Exclusive ownership: `examples/labmitm.yaml`, `examples/mcpjungle/**`, `examples/labinfo/**`
Wave: 8

## Goal

BOM files for adding LabMITM to mcp-integration-lab per `docs/13-integration-lab-add.md`.

## Design references

- [ ] `docs/13-integration-lab-add.md`
- [ ] mcp-integration-lab AGENTS.md rules 8–9, 14

## Scope

- [ ] Overlay YAML `allowLegacyClients: true`, `blockGlobal: false`.
- [ ] MCPJungle server JSON + group append snippet.
- [ ] labinfo service with connection block and CA path.
- [ ] Tests that examples validate (`TestLabOverlayExample`).

## Explicit non-scope

- Merging the lab repo (follow-up human/agent PR there).

## Required tests

- [ ] Example YAML validates with CFG.
- [ ] JSON files parse.
- [ ] Port numbers do not collide with documented family ports.

## Acceptance criteria

- A lab PR can copy files without inventing schema.
