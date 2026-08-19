# Agent Task Plan

Status: Proposed
Last reviewed: 2026-08-18 (FND-001)

This directory divides the initial LabMITM implementation into reviewable work packages. Task files are implementation contracts, not substitutes for normative design documents.

## Working rules

- Read `../AGENTS.md` before taking a task.
- Do not start a task whose required dependencies are incomplete.
- Claim package and schema ownership before editing shared surfaces.
- Keep changes inside the stated ownership boundary unless coordination is recorded.
- Add regression tests for every behavior changed.
- Update all affected documentation in the same pull request.
- All required CI must pass. If CI fails, fix and harden it; do not bypass it.
- Add an unreleased changelog entry for externally observable behavior.
- Do not mark a task complete while TODO tests, skipped checks, stale docs, or unreviewed generated changes remain.

## Task statuses

Use one of:

```text
not-started
in-progress
blocked
in-review
done
```

Update `00-program-board.md` in the coordinating branch rather than creating conflicting status edits from many parallel branches.

## Required task output

Each task produces:

- Code and configuration changes.
- Unit and regression tests.
- Integration or protocol tests where applicable.
- Updated documentation.
- Updated generated contracts where applicable.
- Release-note entry.
- A handoff note listing public surfaces, risks, and follow-on work.

## Program order

Start with `00-program-board.md`. The numbered pack under `docs/` is the source of truth.
