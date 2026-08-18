# H3-001: HTTP/3 and QUIC (1.1)

Status: not-started
Recommended owner: HTTP/3 agent
Dependencies: H2-001; ADR 0011 update to implement
Exclusive ownership: `internal/proxy/h3`, quic-go adapter
Wave: 9 (parallel with PRIV-001)

## Goal

HTTP/3 intercept in reverse/regular as documented by mitmproxy, behind `http3: true`.

## Design references

- [ ] ADR 0011 (must be amended from “later” to “implemented”)
- [ ] `docs/02-proxy-semantics.md`

## Scope

- [ ] New allowed dependency `quic-go` with ADR + license check.
- [ ] UDP listener; container expose 443/udp optional.
- [ ] Schema accepts `http3: true`.
- [ ] Reverse `http3://`.

## Required tests

- [ ] **Integration:** HTTP/3 client to reverse mode (may use quic-go client in test).
- [ ] `http3: false` remains default.

## Acceptance criteria

- Not required for 1.0 tag.
- Parity tools unchanged (flows still HTTP).
