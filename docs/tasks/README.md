# Agent Task Plan

Status: Proposed
Last reviewed: 2026-08-18 (design pack)

This directory divides the initial LabMITM implementation into reviewable work packages. Task files are implementation contracts, not substitutes for normative design documents under `docs/`.

## Working rules

- Read `../../AGENTS.md` before taking a task.
- Do not start a task whose required dependencies are incomplete.
- Claim package and schema ownership before editing shared surfaces.
- Keep changes inside the stated ownership boundary unless coordination is recorded.
- **Add integration tests for every new proxy, REST, MCP, TLS, mode, addon, or replay behavior.**
- Update all affected documentation in the same pull request.
- **All required CI must pass** before a PR is ready and at the end of a PR chain. If CI fails, fix and harden it; do not bypass it. Record non-trivial failures under `docs/ci-failure-hardening/`.
- Maintain REST/MCP parity: no public REST control without an MCP twin except `REST_ONLY_PROTOCOL`.
- Add an unreleased changelog entry for externally observable behavior.
- Do not mark a task complete while TODO tests, skipped checks, stale docs, or unreviewed generated changes remain.

## Task statuses

```text
not-started
in-progress
blocked
in-review
done
```

Update `00-program-board.md` in the coordinating branch rather than creating conflicting status edits from many parallel branches.

## Required task output

Each task produces: code, unit + **integration** tests, updated docs, generated contracts where applicable, changelog entry, and a handoff note.

## Completion evidence

```text
Task ID
Commit or pull request
Design documents read
Files/packages changed
Tests added (unit / integration / parity)
Commands run and results
Generated artifacts changed
Compatibility impact
Security impact
Documentation updated
Release-note entry
Known limitations or follow-ups
CI status (must be green)
```

## Program order

Start with `00-program-board.md`, then use `parallelization-plan.md` to allocate independent lanes.
