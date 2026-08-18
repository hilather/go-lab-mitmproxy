# GA-001: GA Hardening

Status: not-started
Recommended owner: QA / release agent
Dependencies: work packages 1–23 except H3-001 and PRIV-001
Wave: 8

## Goal

1.0 acceptance: fuzz corpora, soak, known-limitations match reality, release notes, all required CI green on the candidate SHA.

## Design references

- [ ] `docs/19-acceptance-criteria.md`
- [ ] `docs/10-testing-strategy.md`
- [ ] `docs/known-limitations.md`

## Scope

- [ ] Commit fuzz corpora.
- [ ] Soak: N flows, wait, wipe (`internal/perf`).
- [ ] Interop matrix documented and tested (curl HTTP/1, H2, WS, SOCKS, reverse).
- [ ] `docs/releases/v1.0.0-rc.1.md` from template.
- [ ] Sweep docs `Last reviewed`.
- [ ] Confirm every PARITY_REQUIRED row has parity tests.
- [ ] Confirm no skipped required tests.

## Required tests

- [ ] Soak default small N in CI.
- [ ] Changelog + notes headings.

## CI requirements

- [ ] **Entire required set green.** If anything fails, fix and harden, then re-run. Do not tag red.
- [ ] End of the 1.0 PR chain is green.

## Acceptance criteria

- Human may tag `v1.0.0-rc.1` on that SHA.
- H3/PRIV remain residuals.
