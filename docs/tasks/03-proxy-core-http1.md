# PROXY-001: HTTP/1 Regular Mode and CONNECT

Status: not-started
Recommended owner: Proxy agent
Dependencies: CFG-001
Exclusive ownership: `internal/proxy/codec`, `internal/proxy/server` (HTTP/1 + CONNECT), `internal/proxytest` HTTP/1 helpers, `testdata/http`
Wave: 2 (parallel with FILT-001, STORE-001)

## Goal

A process can bind regular mode on `127.0.0.1:0` and proxy HTTP/1.1 including CONNECT (TLS bytes spliced until TLS-001).

## Design references

- [ ] `docs/02-proxy-semantics.md`
- [ ] ADR 0002
- [ ] `docs/implementation-design.md` import DAG

## Scope

- [ ] HTTP/1 request parse, hop-by-hop strip, absolute-form and origin-form.
- [ ] CONNECT 200 then splice (passthrough) — intercept TLS in TLS-001.
- [ ] Upstream dial via `net.Dialer` in `internal/proxy` **is allowed** (this is a forward proxy, unlike LabMail).
- [ ] Admission: body size, timeouts from spec.
- [ ] `block_global` / `block_private` enforcement.
- [ ] Session → store.Sink (Null or Memory fake).
- [ ] Import boundary: no `internal/control`.

## Explicit non-scope

- TLS intercept (TLS-001), HTTP/2, WS, SOCKS, reverse (MODE-001).

## Required tests

- [ ] **Integration:** httptest origin + client with `HTTP_PROXY` GET/POST.
- [ ] **Integration:** CONNECT then TLS **passthrough** to httptest TLS origin (client trusts origin cert, not yet lab CA).
- [ ] Hop-by-hop header tests.
- [ ] Missing Host origin-form → 400.
- [ ] block_global true rejects public dest in unit with fake IP classification.
- [ ] Fuzz HTTP/1 codec smoke.

## Acceptance criteria

- curl `-x` HTTP works in integration test.
- CONNECT passthrough works without minting certs.
- PR CI green with new integration tests.
