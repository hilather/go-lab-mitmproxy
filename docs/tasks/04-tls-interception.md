# TLS-001: TLS Interception

Status: not-started
Recommended owner: TLS agent
Dependencies: PROXY-001
Exclusive ownership: `internal/tlsint`, `testdata/tls`, `cmd/labmitm` `ca generate`
Wave: 3

## Goal

Intercept TLS on CONNECT using a mounted (or testdata) CA; mint leaves; `ignore_hosts` splices.

## Design references

- [ ] `docs/23-tls-and-certificates.md`
- [ ] ADR 0012
- [ ] `docs/02-proxy-semantics.md` CONNECT

## Scope

- [ ] Load CA from confDir; fail-closed if missing.
- [ ] `labmitm ca generate`.
- [ ] Leaf mint + memory cache.
- [ ] `upstreamCert` peek when eager.
- [ ] `sslInsecure` default false against testdata CA for upstream.
- [ ] `ignore_hosts` passthrough.
- [ ] Onboarding later ADDON; optional stub 404 until then.

## Required tests

- [ ] **Integration:** curl `--proxy --cacert lab-ca https://httptest/` succeeds and store sees decrypted URL (if STORE Memory wired; else session hook).
- [ ] Ignore host does not mint.
- [ ] Missing CA: serve fails before bind.
- [ ] Key material never appears in slog test spy.

## Acceptance criteria

- HTTPS interception works with generated test CA.
- Ready probe (if OBS not merged) still documented; serve must not bind proxy without CA.
