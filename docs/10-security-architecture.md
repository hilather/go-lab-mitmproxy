# Security Architecture

Status: Proposed normative behavior
Owners: Security, Proxy, Control Plane
Last reviewed: 2026-08-28 (HTTP proxy 407 D76)
Related ADRs: 0002, 0003, 0005, 0007, 0009, 0010, 0012, 0014, 0015, 0016, 0017

LabMITM is a **laboratory intercepting proxy**, not a public edge proxy and not an attack framework. It is a loaded gun: anyone who can reach the proxy can make the process dial arbitrary targets; anyone who can steal the CA can impersonate every host the clients trust that CA for; anyone who can read the management API can exfiltrate captured bodies (often cookies and tokens).

## Threat model

| Threat | Severity | Mitigation |
|---|---|---|
| Open proxy on a published bind used to attack third parties | **Critical** | Default bind `127.0.0.1:8888` (D10); lab overlay documents LAN publish; target guards deny metadata/link-local. Opt-in HTTP 407 (D76) and SOCKS user-pass (D60) are **not** substitutes for a network boundary |
| Stolen lab CA impersonates every HTTPS site the client trusts | **Critical** | Generate-in-memory default (restart rotates); files mode is a mounted secret; never log/export key; `GET /v1/ca` is cert-only and authenticated; UI copy states “lab-only, uninstall after use” |
| Unauthenticated management read of captured bodies | **High** | Default `mode: bearer`; image fixture has a token file; unauthenticated `GET /v1/flows` is 401; no `dev-loopback-unauth` in the image default |
| Body exfil via `mitm.read` token leak | **High** | File-ref tokens ≥256 bits; redaction in logs/export/audit (no `Authorization` / `Cookie` / `Set-Cookie` values in slog); audit records id/host/status/size, not bodies |
| XSS via captured HTML in the operator browser | **High** | No `innerHTML`; default text/escaped view; optional preview iframe `sandbox` without scripts/same-origin; CSP on UI assets |
| SSRF to cloud metadata / link-local | **High** | Resolve-then-guard every A/AAAA; Dial pinned IP; no second lookup (D16). Residual: Alibaba `100.100.100.200`, RFC1918 default-allow |
| Orig-dest spoof / Docker DNAT to `:8890` | **High** | Direct-connect (dest port + local IP); `isHairpin` on both live binds; topologies limited to shared netns + sidecar iptables or host network (D50). Publishing `8890` is not transparent |
| SOCKS BIND advertises IMDS / proxy listen as BND, or listens all-interfaces | **High** | `acceptBind` default off; Listen on control `LocalAddr` IP only (never `:0`); unspecified DST rejected; advertisement filter; hairpin set includes live BIND ports; CIDR + DST-set on inbound peer ([ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) D58) |
| SOCKS UDP ASSOCIATE open relay / amplification / hairpin | **High** | `acceptUDPAssociate` default off; listen on control `LocalAddr` IP only (never `:0`); first datagram pins client UDP source; domain dests pinned (LookupIP once, deny every A/AAAA); CIDR + hairpin drop; inbound flood cap (4096 datagrams or `maxInFlightBytes`); FRAG dropped ([ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) D59, D68) |
| SSRF via Host / CONNECT / absolute-form on orig-dest | **High** | D57: tagged `ServeHTTP` never `serveCONNECT`/`serveAbsolute`; Dial dest IP only; dest IP is CIDR-guarded; never Dial Host/SNI |
| `CAP_NET_ADMIN` on the appliance | **High if granted** | Default image UID 65532, `cap_drop: ALL`; iptables is sidecar/host only (D30) |
| HTTP request smuggling | **Medium** | HTTP/1.1 only; stdlib server parses client hop; we rebuild origin-form rather than blindly copying request-target; fuzz header parser |
| Store memory DoS | **Medium** | Stacked caps + stream-vs-mutate + 64 KiB × maxInFlight slack |
| DNS rebinding on management | **Medium** | Present non-loopback Origin default-deny |
| Supply chain | **Medium** | Pin modules and Actions SHAs; govulncheck; SBOM on release |
| Operator thinks this is a public MITM product | **Medium** | README / START-HERE / UI banner: lab-only; no public CA; no exploit UX |

## Data-plane vs management-plane

- **Proxy HTTP hop:** unauthenticated by default (D17 remainder). Opt-in Basic `Proxy-Authorization` when `spec.proxy.httpAuth.enabled` ([ADR 0017](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0017-http-proxy-407.md) D76): file-ref users, digest side table `HTTPAuthUsers`, constant-time compare, 407 via `ResponseWriter` before Hijack / Dial. Default-off empty `spec: {}` is unchanged. Enabling 407 on a LAN publish is still operator risk. Access control remains bind address + target guards + lab network. HTTP 407 is **not** a substitute for a network boundary. Never log / export / attach username, password, or raw `Proxy-Authorization`. Orig-dest, inner intercept, Replay, and SOCKS are out of this plane.
- **SOCKS:** optional RFC 1929 username/password when `listeners.proxy.acceptUserPass` ([ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) D60). Fail-closed: if the flag is on, NO AUTH (`0x00`) is never selected even if offered. GSSAPI (`0x01`) is never selected. Credentials are file refs compiled into a snapshot side table (`SOCKSUsers` digests); they are not Canonical, not export, not management tokens, and not `internal/auth.Verifier`. Live `replaceRules` / `replaceAdmission` / `replaceTLS` copy `Previous.SOCKSUsers` and must not stat the password files. Matching YAML `id` may appear on `SOCKSInfo.User`; username and password are never logged, exported, or attached to a Flow. **SOCKS user-pass is not a substitute for a network boundary.** Default bind remains `127.0.0.1:8888` (D10).
- **Management:** bearer (D6). Same verifier for REST and MCP. UI exchanges bearer for cookie. No HTTP Basic.

## Dial isolation

```
internal/proxy      may import model, store, rules, tlsmitm, observability, httputilx, http2x
internal/tlsmitm    may import model, observability — handshake only; NO Dial
internal/http2x     codec only (`golang.org/x/net/http2`); NO Dial; DialTLS stays nil
internal/store      may import model, observability
internal/rules      may import model
internal/compiler   may import model, tlsmitm (CA generate/load), config; SOCKS user files on Start/Reset only
internal/snapshot   may import model, rules, tlsmitm
internal/app        may import model, store, snapshot, audit, config, compiler, proxy.Replay, observability
internal/control/*  may import app, capabilities, auth, observability — NOT proxy internals except via app
internal/observability  leaf telemetry only — no domain, snapshot, or control-plane imports
```

Static check (`internal/proxy/import_test.go` plus a repo-wide walk): `Dial`, `DialTimeout`, `Dialer.Dial`, `DialContext`, `DialUDP`, `ListenUDP`, and `ListenPacket` idents are **forbidden by default** in every production `internal/*/*.go` except `internal/proxy`. Explicitly forbidden in `internal/tlsmitm` and `internal/http2x`. Allowed only in `internal/proxy` and `*_test.go` / `internal/proxytest`. Do **not** forbid `net.Listen` (management REST and metrics already bind). A `DialTLS` **field** on `http2.Transport` is allowed only if it stays nil.

## CA private key handling

See [docs/03-tls-interception.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/03-tls-interception.md#ca-private-key-handling). Never log or export the CA private key. `app.Service.GetCA` and `GET /v1/ca` are cert-only. `internal/audit` redacts bearer tokens, secret keys, and any payload containing `BEGIN` + `PRIVATE`.

## Authn/z details

- Tokens: **≥256 bits** entropy, compared as SHA-256 digests. File refs only.
- Failed Bearer returns `401` `unauthenticated` with `WWW-Authenticate: Bearer realm="labmitm"`. MCP is bearer-only (no Basic).
- UI session cookie name **`labmitm_session`**: `HttpOnly`, `SameSite=Lax`, `Secure` iff management TLS; CSRF header `X-LabMITM-CSRF` required on cookie-authenticated mutations even over HTTP (`POST /v1/session`, `DELETE /v1/session`). `GET /v1/session` returns the CSRF secret for a valid cookie (reload recovery). Session JSON (and other REST JSON) is `Cache-Control: no-store`. Token files are reread on reset and apply; the session table is cleared only when the compiled auth identity changes. A failed secret reread keeps the previous verifier and live sessions. Max concurrent sessions: 64.
- No `.well-known/oauth-protected-resource` (ADR 0005).
- `X-Forwarded-For` is not trusted.
- No CORS headers. OPTIONS is not a success path.
- Origin: present non-loopback Origin is rejected unless on `originAllowlist`. Missing Origin is allowed. Only `http`/`https` Origins are accepted.
- Default container YAML is `bearer` (`testdata/container/`). `dev-loopback-unauth` is not the image default.
- No HTTP Basic.

Scopes and roles: [docs/07-control-plane-and-parity.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/07-control-plane-and-parity.md).

## HTML preview / XSS

Default 1.0 view is escaped text. Optional preview iframe (off by default): `sandbox` without `allow-scripts` / `allow-same-origin`, CSP `default-src 'none'`. Never parent `innerHTML` of captured HTML. `GET /v1/flows/{id}/request|response` must not reflect captured `Content-Type`; serve `application/octet-stream` with `Content-Disposition: attachment` and `Content-Security-Policy: default-src 'none'` so a browser GET cannot render captured HTML on the management origin.

## Data handling

- Flow contents are lab data and may contain credentials (cookies, tokens). Treat as secret-adjacent: do not put raw Host in info logs (`host_class=public|lab|ip|unknown` at info); audit “flow.captured” records id, host, status, size, not the body.
- Export of config never includes token values, CA keys, SOCKS passwords, usernames, or `SOCKSUsers` digests.
- `GET` raw request/response is authorized `mitm.read` — operators must understand that.

## Container

Non-root UID 65532, read-only root, no caps, no-new-privileges, no shell, no Docker socket, no writable volume except tmpfs `/tmp` (optional spill `/tmp/labmitm-spill`). Image does **not** contain a lab MITM CA key. Image **must** copy `/etc/ssl/certs/ca-certificates.crt` from the build stage so `x509.SystemCertPool()` is non-empty and default upstream verify works. Transparent orig-dest does **not** add `NET_ADMIN` or change `USER`. iptables REDIRECT lives in a privileged sidecar or on the host ([examples/compose.originaldest.yaml](https://github.com/hilather/go-lab-mitmproxy/blob/main/examples/compose.originaldest.yaml)).
