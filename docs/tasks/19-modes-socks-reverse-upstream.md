# MODE-001: reverse, SOCKS5, upstream

Status: not-started
Recommended owner: Modes agent
Dependencies: TLS-001
Exclusive ownership: `internal/proxy/socks`, reverse/upstream files (not HTTP/1 core)
Wave: 4

## Goal

1.0 extra modes pass documented interop.

## Design references

- [ ] `docs/02-proxy-semantics.md` modes
- [ ] ADR 0002, 0009

## Scope

- [ ] reverse HTTP and HTTPS.
- [ ] SOCKS5 CONNECT only.
- [ ] upstream HTTP proxy chaining.
- [ ] `keep_host_header`, strip Alt-Svc.

## Required tests

- [ ] **Integration:** reverse to httptest.
- [ ] **Integration:** SOCKS5 curl `--socks5-hostname`.
- [ ] **Integration:** upstream to another LabMITM or stdlib proxy stub.
- [ ] UDP ASSOCIATE fails.

## Acceptance criteria

- All three modes green in CI.
