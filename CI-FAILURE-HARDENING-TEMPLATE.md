# CI Failure Hardening Record

Incident/reference:
Date:
Owner:
Failed job:
Commit:

## Failure summary

Describe the observed failure and attach retained logs, reports, seeds, packet captures, or container artifacts.

## Classification

- [ ] Product defect
- [ ] Test defect
- [ ] Race or nondeterminism
- [ ] Fixture/environment defect
- [ ] Dependency or supply-chain change
- [ ] CI pipeline defect
- [ ] Proven transient external dependency

## Root cause

State the root cause. A passing rerun is not a root-cause explanation.

## Immediate fix

Describe the change that makes the affected build correct.

## Hardening added

- [ ] Regression test
- [ ] Better assertion or invariant check
- [ ] Deterministic fixture or fake clock/random source
- [ ] Explicit timeout and cleanup
- [ ] Improved failure diagnostics/artifact retention
- [ ] Dependency or image pinning
- [ ] Resource/race/leak check
- [ ] Narrow bounded retry for a proven external transient
- [ ] Documentation/runbook update

## Why recurrence is less likely

Explain how the hardening detects, prevents, or diagnoses the same failure next time.

## Validation

List local and CI-equivalent commands run and their results.

## Documentation and release impact

State which documents and release-note sections changed.

## Review

- [ ] Root cause reviewed
- [ ] Hardening reviewed
- [ ] All required CI passes
- [ ] No check was bypassed or weakened
