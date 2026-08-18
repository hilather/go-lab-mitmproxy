# Documentation Governance

Status: Proposed normative maintenance policy
Owners: All maintainers
Last reviewed: 2026-08-18 (design pack)

## Policy

Documentation changes ship in the same pull request as the behavior they describe. Stale documentation blocks completion and release.

## Required metadata for numbered `docs/NN-*.md`

```text
Status
Owners
Last reviewed
```

Plus problem/goals/invariants on architecture documents.

## Change rules

- Update a normative document before or with an invariant change.
- Add an ADR for persistence, trust boundary, protocol baseline, or compatibility policy changes.
- Update `Last reviewed` after substantive review.

## Automated checks

`make test-docs` (`scripts/checkdocs` after FND-001):

- Required root files exist.
- Internal-link validation.
- Required metadata on numbered docs.
- Example YAML under `examples/` rejects empty files and tab indents.

Stale generated contracts fail `generated-file`.
