# Security Architecture

Status: Proposed normative behavior
Owners: Security, Proxy, Control Plane
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0002, 0003, 0005, 0009, 0012

LabMITM is a laboratory intercepting proxy. The critical invariants are: authenticated management, a non-exported CA private key by default, HTTP smuggling defenses on, and no privileged network modes in the default image.

## Threat model (lab, not production edge)

See also [docs/20-threat-model.md](20-threat-model.md).

| Threat | Severity | Mitigation |
|---|---|---|
| Open forward proxy to the Internet | **Critical** | `sslInsecure` default false; lab profile documentation; optional destination allowlists; `block_global` documented |
| CA private key theft via MCP/REST | **Critical** | `allowKeyExport` default false; audit; PEM cert-only default tool |
| HTTP request smuggling | High | `validateInboundHeaders` default true; HTTP/1 parser tests; fuzz codec |
| Unauthenticated flow read on published management | High | Default YAML `bearer`; SEC-001 asserts 401; no `dev-loopback-unauth` in the image |
| XSS from captured HTML in operator UI | High | Content views as text/hex/json; sandboxed preview; no parent `innerHTML` |
| SSRF via reverse/map_remote to cloud metadata | High | Reverse targets from YAML only; map_remote validated; no `file:` map_local outside allowDir |
| Confused deputy Basic vs Bearer | Low | One `tokenRef` principal |
| Privileged mode escape (TUN/WG) | High | Not in 1.0 image (ADR 0009) |
| Supply chain | Medium | Pin modules and Actions SHAs; govulncheck; SBOM on release |

## Authn/z

- Tokens: **≥256 bits** entropy, compared as SHA-256 digests. File refs only.
- Basic: exact username + constant-time password; principal `tokens[basic.tokenRef]`.
- Failed auth → `401` `unauthenticated` with `WWW-Authenticate: Bearer realm="labmitm"` and Basic if enabled.
- UI session cookie `labmitm_session` + `X-LabMITM-CSRF` REST-only.
- No `.well-known/oauth-protected-resource`.
- `X-Forwarded-For` is not trusted.
- No CORS. OPTIONS is not a success path.

Scopes: [docs/05-control-plane-and-parity.md](05-control-plane-and-parity.md).

## Proxy admission

- `block_global` / `block_private` as configured. Lab overlay sets `block_global: false` so published clients work. Standalone schema default may match mitmproxy (`true`); **image default YAML used in DEP-001 must set false** and tests must lock it.
- Body size, session caps, header validate.
- `map_local` paths must resolve under `spec.addons.mapLocalAllowDir` (default `/var/lib/labmitm/maplocal`). Path escape → `forbidden`.

## Data handling

- Flows may contain credentials. Do not put URLs, hosts, or Authorization values in metric labels.
- Config export never includes token values, proxyauth passwords, or CA keys.
- slog never logs request bodies at info. `debug` may log header names, not `Authorization` / `Cookie` values.

## Container

Non-root UID 65532, read-only root, no caps, no-new-privileges, no shell, no Docker socket, tmpfs `/tmp`. CA and token mounts are read-only files **0o644** so UID 65532 can read them (LabMail lesson).
