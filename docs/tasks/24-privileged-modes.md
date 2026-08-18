# PRIV-001: Privileged Capture Modes (1.1)

Status: not-started
Recommended owner: Platform/proxy agent
Dependencies: DEP-001; ADR 0009 amendment; **separate compose overlay with capabilities**
Exclusive ownership: `internal/proxy/tun`, `wireguard`, `transparent`, `local` packages
Wave: 9 (parallel with H3-001)

## Goal

Optional privileged image/overlay implementing transparent, TUN, WireGuard, local capture **without** putting caps on the default 1.0 image.

## Design references

- [ ] ADR 0009 (update)
- [ ] mitmproxy mode docs
- [ ] `docs/11-deployment.md`

## Scope

- [ ] New image or compose `cap_add` overlay documented as lab-unsafe-by-default.
- [ ] Schema accepts modes when `spec.proxy.allowPrivilegedModes: true` **and** runtime detects caps.
- [ ] Fail closed in scratch default image.

## Required tests

- [ ] Default image still rejects transparent.
- [ ] Integration tests for privileged modes may be `//go:build privileged` and a non-required CI job **only if** docs/14 is updated — prefer a dedicated required job on runners that support it, or document as manual until infra exists.
- [ ] **Still add integration tests** that run in privileged CI or skip with fail-closed explanation in known-limitations — do not silently skip.

## Acceptance criteria

- 1.0 image unchanged.
- Feature parity for these modes is this task, not a 1.0 claim.
