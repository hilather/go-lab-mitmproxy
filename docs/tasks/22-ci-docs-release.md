# REL-001: CI, Docs, Release Finalization

Status: not-started
Recommended owner: Release agent
Dependencies: FND-001; finalize after API-001 + MCP-001
Exclusive ownership: release-diff script, `release.yml` tag-gate, changelog policy tests
Wave: 0 skeleton / 8 finalize

## Goal

Required CI complete; tag-gate refuses red SHA; release-diff surfaces listed in docs/14.

## Design references

- [ ] `docs/14-release-engineering.md`
- [ ] `RELEASE-NOTES-TEMPLATE.md`
- [ ] `docs/15-documentation-governance.md`

## Scope

- [ ] Early: documentation job (with FND).
- [ ] After catalogs exist: `scripts/release-diff`, `make test-changelog`.
- [ ] `release.yml` tag-gate.
- [ ] Action SHA pins.

## Required tests

- [ ] Changelog test fails without unreleased entry on a dummy path if that's the family pattern.
- [ ] tag-gate logic unit-tested if extracted.

## Acceptance criteria

- No optional CI jobs.
- Agents cannot tag without green required jobs.
