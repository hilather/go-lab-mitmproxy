# ADR 0001: Use Go for the service

Status: Accepted
Date: 2026-08-18

## Context

LabMITM combines a latency-sensitive HTTP/1.1 forward-proxy data plane, in-process TLS intercept, an in-memory flow store, HTTP management, MCP, immutable runtime config, container deployment, race testing, and fuzzing. The family (LabDNS, LabMail, TacLab) is already Go. The repo module is `github.com/hilather/go-lab-mitmproxy`. The toolchain pin is Go 1.26 (D14).

## Decision

Implement the service in Go. Prefer the standard library for HTTP, TLS, concurrency, and crypto. Isolate the official MCP SDK behind an internal adapter. Do not take a third-party proxy or MITM library in 1.0 (ADR 0002).

## Consequences

- A single static binary is easy to deploy as `ghcr.io/hilather/labmitm` (scratch, UID 65532).
- Go concurrency and context cancellation fit proxy session caps, CONNECT Hijack, and store waiters.
- Race detection and fuzzing support hardening.
- Contributors must follow Go memory, cancellation, and error-handling discipline.
- The family CI/Make/docs shape can be copied rather than invented.

## Alternatives considered

- Rust: strong safety and performance, but higher implementation complexity for the initial team and a break from the family.
- Wrap or exec Python mitmproxy: rejected by ADR 0002 / ADR 0007 (plugin VM, no versioned YAML, no family capability registry, no scratch image).
- Third-party Go MITM library (`elazarl/goproxy`, `google/martian`): rejected for 1.0; revisit only if PR 3–4 interop is still red at rc, behind `internal/proxy` via a new ADR.

## Review triggers

Review this decision when its assumptions no longer hold, a major protocol or library change occurs, or a new requirement conflicts with an invariant.
