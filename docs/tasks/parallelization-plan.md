# Parallelization Plan

Status: Proposed
Last reviewed: 2026-08-18

## Principle

Parallelize around stable interfaces, not shared files. Domain types, source schemas, capability registry, error catalog, and generated contracts are high-conflict surfaces and require an explicit owner.

## Wave 0–1

Only FND-001 then CFG-001. No parallel schema edits.

## Wave 2 (after CFG freeze)

Three lanes with **separate packages**:

| Lane | Task | Exclusive |
|---|---|---|
| A | PROXY-001 | `internal/proxy/codec`, `internal/proxy/server` (HTTP/1) |
| B | FILT-001 | `internal/filter`, `testdata/filter` |
| C | STORE-001 | `internal/store` |

PROXY depends on `store.Insert` interface: STORE-001 must land a **stub interface** in CFG-001 (`store.Sink`) or PROXY uses an in-memory fake until STORE merges. **Frozen:** CFG-001 defines `internal/store` interface + Null sink; STORE-001 replaces Null with Memory. PROXY-001 may merge against Null (tests use Memory fake in `proxytest`).

## Wave 3

TLS-001 exclusive `internal/tlsint`. OBS-001 exclusive `internal/observability` and metric names. PROXY must expose hooks (`OnSession`, `OnTLS`) without importing observability types — use a small `internal/proxy/hook` interface owned by PROXY-001.

## Wave 4 (true parallel)

After TLS-001:

- H2-001 owns `internal/proxy/h2` only.
- WS-001 owns `internal/proxy/ws` only.
- MODE-001 owns `internal/proxy/socks`, `internal/proxy/reverse`, `internal/proxy/upstream` files — **not** `server.go` HTTP/1 core. Coordinate listener multiplex in `server/listen.go` via PROXY owner if conflict.
- ADDON-001 owns `internal/addon` and must not edit proxy codecs.

## Wave 6 control plane

After STA-001 freezes `app.Service` methods:

- API-001 owns `internal/capabilities` and `internal/control/rest` and generated OpenAPI merge.
- MCP-001 owns `internal/control/mcp` and `api/mcp/v1.json`; **may not rename capabilities**.
- COMPAT-001 owns `internal/control/compat` only.

If a capability is missing, MCP-001 files a contract issue; API-001 adds the registry row.

## Wave 7–8

SEC-001, SCRIPT-001, DEP-001 parallel after API+MCP exist (SEC can start auth package earlier against fakes). UI-001 after SEC (CSRF). LAB-001 after DEP+MCP. REL-001 skeleton in FND; finalization after generated catalogs.

## Wave 9

H3-001 and PRIV-001 parallel; both require ADRs already on tree (0011, 0009 update).

## Merge order (protects contracts)

```text
FND → CFG → (PROXY ∥ FILT ∥ STORE)
  → TLS → (H2 ∥ WS ∥ MODE ∥ ADDON ∥ OBS)
  → STA → REPLAY
  → API → (MCP ∥ COMPAT)
  → (SEC ∥ SCRIPT ∥ DEP)
  → (UI ∥ LAB ∥ REL ∥ GA)
  → (H3 ∥ PRIV)
```

## Conflict rule

When an agent needs a cross-lane contract change, stop, document, smallest ADR/pack update, coordinate, then edit. Do not silently change capability IDs, YAML fields, or error codes on a feature branch.
