# STORE-001: Flow Store

Status: not-started
Recommended owner: Store agent
Dependencies: CFG-001
Exclusive ownership: `internal/store` Memory implementation, spill, wait
Wave: 2

## Goal

Bounded in-memory flow store with ULID ids, caps, wait, wipe, generation.

## Design references

- [ ] `docs/03-flow-store.md`
- [ ] ADR 0003

## Scope

- [ ] Memory store replacing Null.
- [ ] Insert/update/delete/clear/evict/wipe.
- [ ] `Wait(filter, timeout)` — filter interface from FILT or simple predicate until FILT merges. **Coordinate:** define `store.Matcher func(*model.Flow) bool` so FILT can wrap later.
- [ ] Spill optional under tmpfs path; wipe deletes spill files.
- [ ] Race tests for insert/wait/wipe.

## Required tests

- [ ] Cap reject vs evict_oldest.
- [ ] Wait succeeds on insert; timeout error `timeout`.
- [ ] Wipe empties and bumps generation.
- [ ] Race: `go test -race`.
- [ ] Integration with PROXY if already merged; otherwise unit + fake proxy insert.

## Acceptance criteria

- Store is safe for PROXY and REST waiters.
