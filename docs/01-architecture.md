# System Architecture

Status: Proposed normative behavior
Owners: Architecture, Proxy, Control Plane
Last reviewed: 2026-08-23
Related ADRs: 0001, 0002, 0003, 0004, 0005, 0006, 0007, 0008, 0009, 0010, 0011, 0012

## Problem statement

Laboratory systems under test need a first-party **HTTP(S) intercepting forward proxy** that captures every request and response, can mint a lab CA and per-host leaves to decrypt TLS, and exposes the same authorized operations over native REST `/v1` and MCP `POST /mcp`. Off-the-shelf mitmproxy is a Python attack/research tool: it has a plugin VM, no versioned YAML desired state, no family capability registry, no REST/MCP parity, and no hardened scratch image. `mcp-integration-lab` composes LabMITM (vendor **v1.1.0** + `labmitm:local`). There is **no** predecessor mitmproxy service and **no** mitmproxy HTTP API consumer. Catalog id is **`labmitm`**.

**LabMITM** is a single-process Go lab appliance in the LabDNS / LabMail / TacLab family. Systems under test send HTTP/1.1 absolute-form requests and CONNECT tunnels to a localhost-default proxy bind. Desired state is a fail-closed `labmitm.dev/v1alpha1` YAML file. Captured flows are ephemeral: restart or reset returns the process to the mounted bootstrap and an empty flow store. TLS interception uses an in-process lab CA (generate-in-memory or load PEM files). Rewrite and breakpoint rules are deterministic and default-off. There is no Python addon VM, no public CA, and no LabDNS-style random chaos engine.

## Naming and artifacts

| Kind | Value |
|---|---|
| Product | LabMITM |
| Repository | `github.com/hilather/go-lab-mitmproxy` |
| Go module | `github.com/hilather/go-lab-mitmproxy` |
| Binary / CLI | `labmitm` |
| Image | `ghcr.io/hilather/labmitm` (`:local` for compose builds, digest-pin in GitOps) |
| Container user | `65532:65532` |
| Config schema | `labmitm.dev/v1alpha1` |
| Kind | `LabMITM` |
| Native REST | `/v1` |
| MCP | `POST /mcp` (Streamable HTTP, `Stateless: true`) |
| UI | `/` (SPA) |
| Metrics | Hand-rolled OpenMetrics; default `127.0.0.1:9090`; `/v1/metrics` only if `publicPath: true` |
| Error URN prefix | `urn:labmitm:error:` |
| MCP resource URI | `labmitm://...` |
| Default proxy bind | `127.0.0.1:8888` |
| Default management bind | `127.0.0.1:8088` |
| Healthcheck | `labmitm healthcheck --url=http://127.0.0.1:8088/v1/health/ready` |
| Session cookie | `labmitm_session` |
| CSRF header | `X-LabMITM-CSRF` |

## Port allocation

Family container-internal binds that must not collide:

| Appliance | Data plane (container) | Management (container) | Host (default profile) |
|---|---|---|---|
| LabDNS | `:5353` udp/tcp | `:8080` | `10053` / `18080` |
| LabMail | `:1025` | `:1080` | `1025` / `1080` |
| TacLab | `:49`/`:300`/`:1812`/`:1813` | `:8080` | `18049` |
| LabLDAP | `:3389`/`:3636` | `:8443` | `3389`/`3636`/`8443` |
| labinfo | — | `:8080` | `18090` |
| MCPJungle | — | `:8080` | `8080` |
| **LabMITM** | **`127.0.0.1:8888` standalone / `:8888` lab** | **`127.0.0.1:8088` standalone / `:8088` lab** | **`18888` / `18088`** |
| Metrics (all) | — | `127.0.0.1:9090` | not published |

`:8080` is taken four times. `:8888` and `:8088` are free. Standalone defaults stay loopback (D10). The lab overlay is the place that binds `:8888`/`:8088`.

## Goals (1.0)

1. Single-process Go appliance that accepts HTTP/1.1 absolute-form and CONNECT, optionally intercepts TLS with a lab CA, captures flows, and never wraps or execs Python mitmproxy.
2. Versioned, fail-closed YAML bootstrap; runtime flows ephemeral; reset rereads bootstrap and wipes the flow store.
3. Same authorized flow and state operations on REST `/v1` and MCP `POST /mcp` (parity).
4. Embedded operator flow-inspector UI (React/TS + Vite, Node **22.14.0**) that calls REST only.
5. Hardened container: non-root UID 65532, scratch/static, read-only root, `cap_drop: ALL`, no-new-privileges, tmpfs `/tmp`.
6. In-tree proxy + TLS intercept using stdlib `net/http`, `crypto/tls`, `crypto/x509` only.
7. Bounded flow store (count + bytes + per-body cap) with fail-closed `fullPolicy`.
8. Deterministic, default-off rewrite / breakpoint / delay / inject rules. No random chaos.
9. Structured errors (`urn:labmitm:error:`), audit ring, hand-rolled OpenMetrics, live/ready probes.
10. Design-pack-first repo: numbered normative docs, ADRs, generated contracts, and this PR plan land in-tree in PR 1.

## Non-goals (1.0)

- Reverse-proxy / ingress, transparent TPROXY / iptables redirect, SOCKS4/SOCKS5.
- HTTP/2 or HTTP/3 on the client-facing proxy hop, the intercepted inner connection, or the upstream origin hop.
- WebSocket **frame** inspection (1.0 forwards a `101` upgrade then copies bytes; frames are not decoded).
- mitmproxy Python addon API, mitmproxy `.py` scripts, mitmproxy REST (`/flows`, mitmweb), or any addon VM.
- Wrapping, vendoring, or exec’ing the Python `mitmproxy` binary.
- Third-party proxy libraries (`elazarl/goproxy`, `google/martian`, `projectdiscovery/martian`, etc.).
- Public / well-known CA, ACME, or shipping a CA private key in the image.
- Exploit generation, drive-by install, SSL-stripping as a product feature, or undocumented intercept.
- LabDNS-style weighted / random chaos engine.
- Durable flow-directory persistence, object stores, or databases.
- Multi-replica shared store or consensus.
- OAuth Protected Resource Metadata (family exemption: lab static bearer).
- HTTP Basic on management (no concrete compat consumer; unlike LabMail).
- Proxy-Authorization (data-plane auth) — deferred to 1.1.
- QUIC / HTTP/3, gRPC-over-h2 inspect, DTLS.
- Being a general attack framework or “burp-like” scanner.

## 1.1 opt-in (flags default off)

Additive `labmitm.dev/v1alpha1` fields enable HTTP/2 (inner+origin), SOCKS5/4 CONNECT on the proxy listener, a Linux original-destination REDIRECT listener, and optional compat flow REST. **They default off.** 1.0 defaults remain the process defaults until the operator sets the flags and **Reset**s (D51). CONNECT calls the extracted `serveInterceptConn` helper. `protocols.http2` feeds Handshake NextProtos from the session snapshot (D46); when enabled and the leaf ALPN is `h2`, inner streams are captured via `roundTripInnerH2` and transcoded onto one HTTP/1.1 origin TCP (D44). The proxy accept mux peeks in a per-conn goroutine (D42) and SOCKS-closes `0x04`/`0x05` while `acceptSOCKS5`/`acceptSOCKS4` are false. When those flags are on, SOCKS5/4 CONNECT (NO AUTH) is multiplexed on `listeners.proxy` and calls `serveInterceptConn` without an HTTP 200. HTTP CONNECT still writes 200 then intercepts. Orig-dest is a separate Linux REDIRECT listener (D50). Compat flow REST is an after-auth adapter under a configurable prefix (default `/compat`).

- [ADR 0008](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0008-additive-v1alpha1-11.md): additive schema; reserved keys stay; flags are bootstrap + **Reset only** (D51).
- [ADR 0009](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0009-http2-via-http2x.md): supersedes ADR 0002 **D8 scope only**. **D7 stands.**
- [ADR 0010](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0010-socks-and-original-destination.md): supersedes the “TPROXY/SOCKS are 1.1+” **sentence**. TPROXY stays rejected.
- [ADR 0011](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0011-optional-compat-flow-rest.md): supersedes ADR 0007 D5’s “no compat path in 1.0” **sentence**. Native `/v1` + MCP primacy stands. `/compat` is **not** on `catalog()` / `compileRoutes`.

**D7 stands.** In-tree proxy, no third-party MITM library, CONNECT Hijack. Legal YAML names are camelCase (`acceptSOCKS5`, `originalDestination`, `protocols.http2`, `compat.flowREST`). Reserved `socks*` / `tproxy` / `mitmproxy*` keys stay reserved.

## 1.2 opt-in (flags default off)

[ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) records **D58–D68**. Client-facing h2c, SOCKS BIND / UDP ASSOCIATE, SOCKS username/password, Extended CONNECT websocket, origin `h2`, `PUSH_PROMISE` capture, gRPC decode, and WebSocket frame inspect are 1.2-class, default-off, Reset-only (D51). Empty spec remains 1.0. Overlay YAML stays flags-off. Nested inner CONNECT without `:protocol` still RST (**no flow**). No `Proxy-Authorization`. GSSAPI remains a non-goal. **D7 stands.**

## Key decisions

These are closed. Implementers do not re-litigate them without an ADR.

| ID | Decision | Rationale |
|---|---|---|
| **D1** | **Product name is LabMITM.** Repo remains `go-lab-mitmproxy`. Module `github.com/hilather/go-lab-mitmproxy`. Binary / CLI `labmitm`. Image `ghcr.io/hilather/labmitm`. YAML `apiVersion: labmitm.dev/v1alpha1`, `kind: LabMITM`. | LabMail naming rule. TacLab is the frozen exception (ADR 0018). |
| **D2** | **Single process, two planes.** Proxy data plane is independent of management HTTP. Invalid bootstrap does **not** bind either listener. | LabDNS / LabMail process model. |
| **D3** | **Desired state is YAML; the flow store is not.** Reset reloads YAML **and** wipes flows. | Family GitOps invariant. |
| **D4** | **REST and MCP share one capability registry.** Adapters never call each other. | LabDNS / LabMail ADR 0004. |
| **D5** | **Native management API is `/v1` + `POST /mcp` only.** No mitmproxy REST, no mitmweb, no Python addon protocol. | Zero mitmproxy API clients in the lab. |
| **D6** | **Auth: lab static bearer is primary. No HTTP Basic in 1.0.** | No Basic consumer. Tokens ≥256 bits, file refs only. |
| **D7** | **In-tree HTTP/1.1 forward proxy.** No third-party proxy library. CONNECT **must** Hijack (D19). | Family owns protocol state machines. |
| **D8** | **HTTP/1.1 only on every hop in 1.0.** HTTP/2 preface is a hard close. | Intercepting h2 requires a frame codec the family does not own. |
| **D9** | **TLS intercept is in-process lab CA + per-host leaf minting.** `generate` or `files`. Never ship a public CA. Never log the CA private key. | Lab-only intercepting proxy. |
| **D10** | **Default proxy bind is `127.0.0.1:8888`. Default management bind is `127.0.0.1:8088`.** Explicit LabMail deviation (LabMail defaults are all-interfaces). | An intercepting proxy is an open-proxy loaded gun. |
| **D11** | **Store is memory-first with stacked caps.** Default `fullPolicy: reject`. Store-full **still forwards**. | Prevents OOM. Capture is best-effort. |
| **D12** | **No chaos engine in 1.0.** `spec.rules` is deterministic, default-off, first-match-wins. | A capture appliance’s job is explainable behavior. |
| **D13** | **Embedded flow-inspector UI ships in 1.0.** React + TypeScript + Vite, Node **22.14.0**. Frozen table: [Embedded operator UI](#embedded-operator-ui). | Family replacement contract. GA is not done without PR 13. |
| **D14** | **Go 1.26, official MCP SDK `v1.7.0`, protocol `2026-07-28`, Apache-2.0.** `KnownFields(true)`. CI pin `GO_VERSION=1.26.6`. | Family pins. |
| **D15** | **`allowLegacyClients` default false; lab overlay sets true.** `subscriptions/listen` stays 2026-07-28. | So MCPJungle can register without a LabMITM patch. |
| **D16** | **Data-plane Dial is required, isolated, and resolve-then-guard.** Dial only in `internal/proxy`. | Hostname-only guards miss CNAME→IMDS. |
| **D17** | **Proxy HTTP hop is unauthenticated.** No `Proxy-Authorization`. 1.2 supersedes the unauthenticated-data-plane sentence **for SOCKS only** ([ADR 0012](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0012-protocol-expansion-12.md) D60): opt-in file-ref username/password; GSSAPI out; management still bearer (D6). | Lab clients (`curl --proxy`) must keep working. Binding localhost is the 1.0 access control. SOCKS user-pass is a second lab-static plane, default-off, fail-closed. |
| **D18** | **Catalog id is `labmitm`.** Lab pin is vendor tag **v1.1.0** + `labmitm:local` (not a GHCR digest). | No predecessor to preserve. |
| **D19** | **CONNECT Hijack + inner HTTP/1.1 session.** Never return that conn to `http.Server`. | Returning after 200 makes keep-alive parse the TLS ClientHello as a request. |
| **D20** | **`intercept: true` does not silently tunnel.** Handshake failure closes both sides. | Silent fallback would hide a failed MITM. |
| **D21** | **`Transport.RoundTrip` only; no `http.Client`.** Replay Dials the origin, ignores `HTTP_PROXY`, never hairpins. | `Client.Do` follows redirects and would merge hops. |

## Process architecture

One `labmitm` process. Invalid bootstrap does **not** bind proxy or management.

```mermaid
flowchart LR
  subgraph testers [Systems under test]
    APP[HTTP client / app]
  end
  subgraph operators [Operators and agents]
    UI[Browser flow inspector]
    REST[REST client]
    MCP[MCP client / MCPJungle]
  end
  subgraph labmitm [labmitm process]
    PROXY["127.0.0.1:8888 HTTP/1.1 proxy + CONNECT"]
    HTTP["127.0.0.1:8088 UI / REST / MCP"]
    TLS[internal/tlsmitm]
    REG[Capability registry]
    APPSvc[internal/app.Service]
    STORE[Flow store]
    SNAP[Immutable config snapshot]
    AUDIT[Audit ring]
  end
  YAML[(read-only bootstrap YAML)] --> SNAP
  APP -->|absolute-form / CONNECT| PROXY
  PROXY --> TLS
  TLS -->|dial origin| UP[Upstream origin]
  PROXY --> STORE
  UI --> HTTP
  REST --> HTTP
  MCP --> HTTP
  HTTP --> REG --> APPSvc
  APPSvc --> STORE
  APPSvc --> SNAP
  APPSvc --> AUDIT
  PROXY -.->|does not call| HTTP
```

```text
HTTP/1.1 proxy wire
  -> admission (conns, rate, size, target guards)
  -> request parse (absolute-form | CONNECT)
  -> rules (request phase)
  -> optional TLS intercept (internal/tlsmitm)
  -> upstream dial + HTTP/1.1 exchange
  -> rules (response phase)
  -> store.Insert (capped bodies)
  -> metrics + optional audit "flow.captured"

REST adapter ----+
MCP adapter -----+--> capabilities registry --> app.Service
UI (static) -----> REST only                    -> store / snapshot / audit / rules
```

**Invariant:** `internal/proxy` and `internal/tlsmitm` must not import `internal/control` (including `internal/control/mcp` and `internal/control/rest`) or `internal/web`. Management failure must not stop the proxy. The proxy must not block on MCP clients.

## Embedded operator UI

Required for GA / 1.0 (D13, PR 13). The UI talks REST only. XSS/CSP: [docs/08-rest-api.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/08-rest-api.md) and [docs/10-security-architecture.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/10-security-architecture.md).

| Item | Choice |
|---|---|
| Stack | React + TypeScript + Vite (Node 22.14.0), LabMail/TacLab pattern |
| Embed | `internal/web` `go:embed` of `web/dist` (copy step; `web/` has its own `go.mod` so parent `go test ./...` does not walk `node_modules`) |
| Auth | Login page: paste bearer. `POST /v1/session`. Cookie `labmitm_session` + `X-LabMITM-CSRF`. Cookie is REST-only. No Basic form. |
| Pages | Flow list, flow detail (protocol badge, HTTP/2 stream id, headers / trailers / textual or hex body / TLS / download, SOCKS dest, original dest), CA download (`GET /v1/ca`; `ca.spkiSha256` on status), status, audit (if scoped), gated reset |
| Live update | `EventSource` `GET /v1/events/stream` (SSE). Fallback: 3s poll of `GET /v1/flows`. |
| Bodies | Render as text if `Content-Type` is text/*, json, xml, form; otherwise hex/size + download. Never `innerHTML` of response HTML. Download is `download=` plus blob fetch; raw body GETs are `application/octet-stream` + attachment. Optional iframe preview **only** with `sandbox` (no scripts, no same-origin) and CSP `default-src 'none'` — default **off**. |
| Missing on purpose | Fuzzer, repeater-as-weapon, payload generator, “exploit”, SSL-strip toggle, Relay |

`spec.ui.enabled: false` serves 404 for `/` but keeps REST/MCP.

## Package layout

```text
.
|-- AGENTS.md
|-- README.md
|-- START-HERE.md
|-- LICENSE                          # Apache-2.0
|-- CHANGELOG.md
|-- Makefile
|-- go.mod                           # github.com/hilather/go-lab-mitmproxy
|-- Dockerfile
|-- cmd/labmitm/                     # process entrypoint only
|-- internal/
|   |-- model/                       # Spec, Flow, Message, Operation, Rule
|   |-- config/                      # decode, KnownFields, normalize, validate, hash, export
|   |-- compiler/                    # spec → snapshot (rules index, CA handle, caps)
|   |-- snapshot/                    # atomic config snapshot
|   |-- store/                       # flow inbox
|   |-- proxy/                       # HTTP/1.1 forward proxy listener + session
|   |-- tlsmitm/                     # lab CA, leaf mint, dual TLS
|   |-- httputilx/                   # hop-by-hop strip, header fold; NOT httputil.ReverseProxy
|   |-- rules/                       # first-match evaluate (compiler snapshot is STA-001)
|   |-- app/                         # Service (no HTTP/MCP types)
|   |-- capabilities/                # registry
|   |-- control/rest/
|   |-- control/mcp/
|   |-- auth/
|   |-- audit/
|   |-- domainerr/
|   |-- observability/
|   |-- buildinfo/
|   |-- web/                         # embed SPA
|   `-- proxytest/                   # test client; *_test.go only
|-- api/
|-- web/
|-- docs/
|-- examples/
|-- testdata/
|-- scripts/{generate,checkdocs,checkchangelog,test-container.sh}
`-- tasks/
```

`cmd/labmitm` contains no protocol or store logic.

## Allowed third-party direct deps at 1.0

| Module | Why |
|---|---|
| `gopkg.in/yaml.v3` | Family config |
| `github.com/modelcontextprotocol/go-sdk v1.7.0` | Family MCP |
| `github.com/oklog/ulid/v2` | Crockford ULID flow ids (MIT; LabMail pin) |

1.1 codec (ADR 0009 / D28): `golang.org/x/net/http2` behind `internal/http2x` only (BSD-3, Apache-2.0 compatible). Not a proxy/MITM library. Dial idents forbidden; `DialTLS` stays nil.

No Prometheus client (`github.com/prometheus/*` forbidden). Metrics are hand-rolled OpenMetrics in `internal/observability`. No proxy/MITM frameworks. Prefer `net/http`, `log/slog`, `crypto/tls`, `crypto/x509`, `crypto/ecdsa`. New deps need a PR justification and Apache-2.0-compatible license check.

## Canonical data model

Canonical Go types in `internal/model` (implemented in CFG-001 / STORE-001):

```go
type Spec struct {
    Listeners     ListenersSpec
    Proxy         ProxySpec
    TLS           TLSSpec
    Rules         RulesSpec
    Store         StoreSpec
    UI            UISpec
    Management    ManagementSpec
    Observability ObservabilitySpec
}

type Flow struct {
    ID           string
    StartedAt    time.Time
    CompletedAt  time.Time
    State        string // open | paused | completed | dropped | error
    PausedPhase  string // request | response | ""
    ClientAddr   string
    Method       string
    URL          string
    Host         string
    Scheme       string // http | https
    Protocol     string // http/1.1 | websocket | connect
    Status       int
    Error        string
    Intercepted  bool
    Request      HTTPMessage
    Response     HTTPMessage
    TLS          *TLSInfo
    Timings      Timings
    RuleIDs      []string
    Truncated    bool
}
```

## CLI

```text
labmitm serve --config=/etc/labmitm/config.yaml
              [--proxy-listen ADDR] [--management-listen ADDR|off]
              [--shutdown-timeout 5s] [--pid-file /tmp/labmitm.pid]
labmitm validate --config=...
labmitm canonicalize --config=... [--format yaml|json]
labmitm healthcheck --url=http://127.0.0.1:8088/v1/health/ready
labmitm mcp-stdio --config=... --token-file=...
labmitm version
labmitm help
```

There is **no** `serve --token-file`. `labmitm send` / `labmitm request` are **not** shipped.

TLS-001 implements `serve` with optional HTTPS intercept (`tls.intercept: true`, default ports `{443}`). API-001 binds management REST when `--management-listen` is an address **and** `management.auth.mode: bearer` has ≥1 usable token. Missing token files fail serve. `--management-listen=off` leaves management unbound. OBS-001 implements `labmitm healthcheck` and the `127.0.0.1:9090` scrape listener.

## Invariants

1. Proxy request handling does not depend on REST or MCP availability.
2. Invalid bootstrap does not bind proxy or management.
3. REST and MCP call the same application capabilities.
4. Bootstrap YAML is read-only to the service.
5. Unknown configuration fields are errors.
6. Dial is isolated to `internal/proxy`.
7. Runtime flows are ephemeral and do not set `drifted`.
8. `internal/proxy` and `internal/tlsmitm` do not import management packages.
9. CONNECT is Hijacked and never returned to `http.Server`.
10. Intercept handshake failure does not fall back to a blind tunnel.

## Residual limitations

See [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/known-limitations.md). 1.0 defaults remain the process defaults.

- HTTP/3 / QUIC still out. HTTP/2 inner is `protocols.http2.enabled` (default off). Client-facing h2c is `protocols.http2.clientCleartext` (default off, Reset-only); flag-off `PRI` is still a hard close.
- No Python VM, mitmweb, dumpfile, CLI-flag clone, or wrapping Python mitmproxy.
- No TPROXY in the appliance (`tproxy` reserved). No reverse-proxy.
- Orig-dest is Linux-only REDIRECT + `SO_ORIGINAL_DST`, default off. Supported topologies are shared-netns + sidecar iptables or host-network REDIRECT (D50). Publishing `8890` is not transparent.
- Compat flow REST is a mitmproxy-inspired **subset** (default off, Reset-only). Not mitmproxy 11 compatible.
- SOCKS5/4 CONNECT is opt-in, NO AUTH, CONNECT only. BIND/UDP/GSSAPI/password are out.
- 1.1 flags (`acceptSOCKS5`/`acceptSOCKS4`, `originalDestination`, `protocols.http2`, `compat.flowREST`) are bootstrap + **Reset only** (D51).
- WebSocket frames: flag-off is 101 + bidirectional copy; flag-on `protocols.websocket.inspectFrames` (Reset-only, D67). Inner RFC 8441 `:protocol=websocket` is opt-in `protocols.http2.extendedConnect` (D63); nested inner CONNECT without `:protocol` still RST, **no flow**. Client-facing Extended CONNECT / h2c is still out.
- Generate-mode CA rotates on every restart/reset.
- Store-full still forwards (capture dropped).
- Single replica; no shared flow store.
- MCP clients requiring OAuth PRM cannot authorize. MCPJungle needs `allowLegacyClients: true`.
- Proxy data plane unauthenticated; publishing `:8888` on a LAN is an operator choice.
- No Proxy-Authorization. No HTTP Basic on management.
- HTML preview of captured pages is escaped text.
- Intercept **breaks origin mTLS and certificate pinning**.
- Default metadata CIDRs are AWS/GCP IPv4 + AWS IPv6 IMDS. Alibaba `100.100.100.200/32` and RFC1918 are **not** default-deny.
- Not a general attack tool.
- Worst-case RSS ≈ 256 + 64 + 4 + 64 = **388 MiB**.
- Default soak in CI is 8 flows; local lab target is 100 flows/s for 30s. Absolute QPS is not a CI gate.
- Overlay examples live in this repo. Lab pin is vendor tag **v1.1.0** + `labmitm:local` (not a GHCR digest). Catalog id is **`labmitm`** (D18).

## Related documents

- Proxy semantics: [docs/02-proxy-semantics.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/02-proxy-semantics.md)
- TLS: [docs/03-tls-interception.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/03-tls-interception.md)
- Store: [docs/04-flow-store.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/04-flow-store.md)
- YAML: [docs/06-state-and-configuration.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/06-state-and-configuration.md)
- Capability table: [docs/07-control-plane-and-parity.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/07-control-plane-and-parity.md)
