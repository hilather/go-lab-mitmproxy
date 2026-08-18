# REPLAY-001: Replay and Export

Status: not-started
Recommended owner: Replay agent
Dependencies: STA-001
Exclusive ownership: `internal/replay`, `internal/dump`, `internal/contentview`
Wave: 5

## Goal

Client replay, server replay (knobs in spec), HAR 1.2, JSONL dump import/export, content views.

## Design references

- [ ] `docs/03-flow-store.md`
- [ ] ADR 0010 (no Python dump writer)

## Scope

- [ ] Client replay creates new flow.
- [ ] Server replay matching + extra policy.
- [ ] HAR export/import documented subset (HTTP/1 GET/POST).
- [ ] JSONL `labmitm-dump-v1`.
- [ ] Content views: raw, hex, json, urlencoded at minimum.

## Required tests

- [ ] **Integration:** capture GET, client replay, second flow marked replay.
- [ ] **Integration:** server replay returns stored response with origin down (`connection_strategy=lazy`).
- [ ] HAR round-trip fixture.
- [ ] JSONL round-trip fixture.

## Acceptance criteria

- Offline server replay works in CI.
