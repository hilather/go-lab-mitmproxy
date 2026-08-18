# ADR 0001: Use Go for the service

Status: Accepted
Date: 2026-08-18

## Context

LabMITM combines a latency-sensitive intercepting proxy, TLS interception, an in-memory flow store, HTTP management, MCP, immutable runtime config, container deployment, race testing, and fuzzing. The family (LabDNS, LabLDAP, TacLab, LabMail) is already Go. The toolchain pin is Go 1.26 (D14).

## Decision

Implement the service in Go. Prefer the standard library for HTTP/1, TLS, and concurrency. Isolate the official MCP SDK, `golang.org/x/net/http2`, and Starlark behind internal adapters.

## Consequences

- A single static binary deploys as `ghcr.io/hilather/labmitm` (scratch, UID 65532).
- Race detection and fuzzing support hardening.
- The family CI/Make/docs shape can be copied rather than invented.

## Alternatives considered

- Keep wrapping Python mitmproxy: no family YAML/MCP/parity; rejected (ADR 0010).
- Rust: strong safety, but a break from the family and slower 1.0 delivery.
- goproxy / martian wrappers: less control over intercept/replay/parity; rejected (ADR 0002).

## Review triggers

Review when the family leaves Go or HTTP/3 forces a runtime we cannot bind in-process.
