# TLS and Certificates

Status: Proposed normative behavior
Owners: TLS, Security
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0012

## CA

The lab CA is a **secret mount**, not ephemeral runtime state.

Layout under `spec.tls.confDir`:

- `labmitm-ca.pem` — certificate + unencrypted private key (or passphrase via `certPassphraseFile`)
- `labmitm-ca-cert.pem` — certificate only (download / mitm.it)

`labmitm ca generate --out DIR` creates a unique CA (`keyUsage=critical,keyCertSign`, `CA:TRUE`, 2048-bit RSA default `keySize`). `serve` never generates a CA.

Accept `mitmproxy-ca.pem` as an alias filename so operators can drop an existing mitmproxy CA into the mount.

## Leaf minting

On intercepted TLS ClientHello:

1. If `upstreamCert` (default true) and a server connection is allowed: peek upstream certificate for CN/SAN/org (eager strategy).
2. Mint a leaf signed by the lab CA with matching SAN, cache by `(sni, spki-or-san-set)` with TTL 24h in memory.
3. Complete handshake with the client using the minted leaf.

`certs` entries override minting for listed hosts.

`addUpstreamCertsToClientChain` extra-chain as documented.

## Versions and ciphers

Defaults: client/server min TLS 1.2. SSL3/TLS1/TLS1.1 require explicit YAML and `mitm.admin` audit on apply. Cipher strings: if set, parse via `crypto/tls` cipher suites; OpenSSL-name mapping is a documented table in TLS-001 — unknown names fail validate.

## Upstream verification

`sslInsecure: false` default. `trustedCAFile` optional. Image default must not set insecure.

## mTLS

- `requestClientCert`: send CertificateRequest to the client (no verification of identity in 1.0; captured cert logged as present/absent only).
- `clientCerts`: file or directory of PEM client certs for **upstream** mTLS.

## Onboarding

`mitm.it` (configurable host) serves cert downloads, never the key. See [docs/02-proxy-semantics.md](02-proxy-semantics.md).

## Certificate pinning

Documented as a residual: pinning apps will fail intercept. Use `ignore_hosts` or patch the SUT. LabMITM does not ship Frida/apk-mitm.
