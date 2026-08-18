# ADR 0005: Lab static bearer (no HTTP Basic)

Status: Accepted
Date: 2026-08-18
Decisions: D6

## Context

The family (TacLab ADR 0010, LabDNS bearer, LabMail ADR 0005) uses lab static bearer tokens, not OAuth Protected Resource Metadata. LabMail added HTTP Basic because `maildevScenario` required it. LabMITM has **no** concrete compat consumer that needs Basic.

## Decision

**D6 — Lab static bearer is primary. No HTTP Basic in 1.0.**

- Default YAML `management.auth.mode: bearer`.
- Tokens ≥256 bits, compared as SHA-256 digests. File refs only. Reject `environment:` as unknown. No `LABMITM_ALLOW_ENV_SECRETS`.
- MCP is bearer-only.
- No `.well-known/oauth-protected-resource`.
- UI session cookie `labmitm_session` + `X-LabMITM-CSRF` is REST-only.
- `dev-loopback-unauth` is not the image default.
- Binding management with `mode: bearer` and zero usable tokens is **refused** (do not listen allow-all).

## Consequences

- One verifier, one scope matrix.
- MCPJungle uses `LABMITM_TOKEN`.
- A later lab UI that cannot paste a bearer can add Basic behind a new ADR.
- Image/default fixtures are not `dev-loopback-unauth`. After SEC-001, unauthenticated `GET /v1/flows` is 401.

## Alternatives considered

- Bearer + Basic (LabMail D6): no consumer here. Widens the auth matrix for no gain. Rejected.
- OAuth PRM: family exemption for lab static bearer. Rejected.
- Default `dev-loopback-unauth`: rejected. An intercepting proxy with an open management API would leak captured bodies.

## Review triggers

Review this decision when a concrete Basic consumer appears, when OAuth PRM becomes a hard MCP client requirement, or when a second principal model is proposed.
