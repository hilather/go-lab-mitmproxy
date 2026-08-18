# FILT-001: Filter Language

Status: not-started
Recommended owner: Filter agent
Dependencies: CFG-001
Exclusive ownership: `internal/filter`, `testdata/filter`
Wave: 2

## Goal

Parse and evaluate mitmproxy-compatible filters with RE2.

## Design references

- [ ] `docs/24-filter-language.md`

## Scope

- [ ] Parser + evaluator for every operator in the table.
- [ ] Stable parse errors.
- [ ] `testdata/filter/cases.json` positive/negative per operator.

## Explicit non-scope

- `@focus` without focusId (return validation error — implement).

## Required tests

- [ ] Table-driven cases.json.
- [ ] RE2 reject of invalid Python-only regex (if we can detect; otherwise document).
- [ ] Integration: used by STORE wait once both merged — add in the later of the two PRs.

## Acceptance criteria

- Full operator table green.
