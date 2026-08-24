# Repository Instructions for Agents

These instructions apply to every human or AI agent working in this repository. More specific `AGENTS.md` files may add stricter rules but may not weaken this file.

## Required reading

Before modifying code, read:

1. `docs/01-architecture.md`
2. `docs/02-proxy-semantics.md`
3. `docs/03-tls-interception.md`
4. `docs/04-flow-store.md`
5. `docs/05-rules.md`
6. `docs/06-state-and-configuration.md`
7. `docs/07-control-plane-and-parity.md`
8. `docs/10-security-architecture.md`
9. `docs/12-testing-strategy.md`
10. Every ADR relevant to the area being changed

The numbered pack is the source of truth after FND-001. Do not invent paths, types, regexes, validate rules, or capability IDs. If an invariant must change, write an ADR first.

## Architectural rules

- REST and MCP are adapters. Domain behavior belongs in `internal/app`, `internal/store`, `internal/proxy`, `internal/tlsmitm`, `internal/rules`, `internal/config`, or `internal/model`.
- REST handlers and MCP handlers must never implement independent business logic and must never call each other.
- Every public capability must be represented in the central capability registry.
- The proxy must keep accepting if REST/MCP is slow or unbound (`--management-listen=off`). `internal/proxy` and `internal/tlsmitm` must not import `internal/control` or `internal/web`.
- Production `Dial` / `DialTimeout` / `Dialer.Dial` / `DialContext` idents are allowed **only** in `internal/proxy` and `*_test.go` / `internal/proxytest`. Forbidden in every other `internal/*` production file, including `internal/tlsmitm` (handshake only on an already-dialed conn).
- Resolve-then-guard: parse authority → literal CIDR check or `LookupIP` then check **every** A/AAAA → Dial a selected allowed IP with no second resolve. Default-deny cloud metadata and link-local; loopback allowed (lab apps).
- The config loader rejects reserved attack/compat keys (`socks`, `tproxy`, `publicca`, `addon`, `exploit`, `sslstrip`, `mitmproxy`, …) after normalize (strip dashes, underscores, and case).
- Desired state is YAML. The flow store is not. Reset rereads bootstrap **and** wipes flows.
- The service must not write to the bootstrap configuration file.
- Do not add a database, flow-directory, hidden volume, or other persistence mechanism without an approved ADR.
- Do not import third-party proxy/MITM libraries (`elazarl/goproxy`, `google/martian`, …). Do not wrap, vendor, or exec Python mitmproxy (ADR 0002, ADR 0007).
- HTTP/1.1 only on every hop in 1.0. No HTTP/2 or HTTP/3. `PRI * HTTP/2.0` is a hard close. 1.1 may enable HTTP/2 on the **inner + origin** hops via `protocols.http2` (default off, Reset-only). 1.2 may enable client-facing h2c when `protocols.http2.clientCleartext` (default off, Reset-only); flag-off PRI still hard close. **D7 stands.**
- On `CONNECT`, `Hijack` before any body and never return that conn to `http.Server` (D19).
- `intercept: true` does not silently tunnel on handshake failure (D20).
- `Transport.RoundTrip` only; never `http.Client` / `Client.Do` (D21). Replay Dials the origin, ignores `HTTP_PROXY`, never hairpins `listeners.proxy.address`.
- Do not add a random/probabilistic chaos / fault-injection engine in 1.0 (D12). Deterministic, default-off `spec.rules` is the allowed QA knob.
- The embedded flow-inspector UI is required for GA / 1.0 (PR 13). Do not ship 1.0 without it.
- No mitmproxy REST, mitmweb, or Python addon surface in 1.0 (ADR 0007). 1.1 optional compat flow REST is a first-party adapter (ADR 0011), default-off, Reset-only. Do **not** put `/compat` on `catalog()` / native `compileRoutes`. `CompatBindings()` is a side table matched after authenticate/authorize.
- 1.1 flags (`acceptSOCKS5`/`acceptSOCKS4`, `originalDestination`, `protocols.http2`, `compat.flowREST`) are bootstrap + Reset only (D51). `acceptSOCKS5`/`acceptSOCKS4` enable SOCKS CONNECT on the proxy listener (NO AUTH; peek replay; `gate.acquire` after the request; `serveInterceptConn` without HTTP 200). Flags off keep 1.0 SOCKS-close. `protocols.http2` feeds Handshake NextProtos from the session snapshot (D46). When the flag is on and the leaf ALPN is `h2`, inner capture runs via `http2x.ServeClient` / `roundTripInnerH2` (D53); inner CONNECT without `:protocol` and illegal h2 `Upgrade: websocket` stay RST, **no flow** (D48 remainder). Flag-off or inner `http/1.1` `PRI` still `http2_inner`. `protocols.http2.clientCleartext` (default off, Reset-only) enables client-facing h2c on PRI leftover (`http2x.ServeConn` PrefaceTail; do not re-read the 24-byte preface from the raw conn); flag-off PRI still hard close before `gate.acquire`. RFC 9113 CONNECT on that session is one origin TCP per stream (D62): 2xx HEADERS then raw splice or intercept AfterAck (no HTTP/1.1 200); handshake failure is not a DATA tunnel (D20). Orig-dest tagged CONNECT stays 400. `originalDestination.enabled` binds the Linux REDIRECT listener (D30); dest-IP Dial only (D57). Ready uses OrigDestBound||OrigDestOff. h2 inner transcodes onto one HTTP/1.1 origin TCP: mutex covers RoundTrip and full body drain, MaxConnsPerHost 1 (D44). Replay of an h2 flow is HTTP/1.1 origin-form with leading-`:` names stripped unless live `protocols.http2.origin` is on. **D7 stands.**
- 1.2 flags are bootstrap + Reset only (D51): `listeners.proxy.acceptBind` / `acceptUDPAssociate` / `acceptUserPass`, `protocols.http2.clientCleartext` / `origin` / `extendedConnect` / `capturePush` / `grpcDecode`, `protocols.websocket.inspectFrames`. Empty `spec: {}` materializes all false. 1.1 `acceptSOCKS5` remains CONNECT-only unless `acceptBind` / `acceptUDPAssociate` / `acceptUserPass`. Unspecified BIND DST is rejected. GSSAPI is never selected. Nested inner CONNECT without `:protocol` still RST, no flow. grpc-web stays opaque. Overlay YAML stays flags-off. Catalog stays 30 `/v1` rows. No new capability IDs. **D7 stands.**
- No HTTP Basic on management in 1.0 (no compat consumer). Auth is lab static bearer.
- Default binds are loopback `127.0.0.1:8888` / `127.0.0.1:8088` (D10). Empty address materializes those defaults, not `:8888`.
- Hide third-party MCP and YAML library types behind internal adapters.

## Tests and regressions

- Every area must have regression tests.
- Every code path, protocol behavior, API capability, configuration semantic, operational script, and bug fix must have appropriate automated regression coverage.
- A bug fix must begin with or include a test that fails before the fix and passes after it.
- New proxy behavior requires session transcripts over `internal/proxytest`.
- New REST functionality requires contract tests and shared-domain tests.
- New MCP functionality requires protocol tests and REST/MCP parity tests.
- Configuration changes require valid, invalid, reserved-key, normalization, and revision tests.
- Never delete or weaken a test merely to make CI pass unless the test is provably incorrect; document the reason in the change.

## CI is mandatory

- All required CI checks must pass before merge and before a release tag is created.
- Do not bypass, skip, mark optional, or administratively override a failing check to ship a change.
- Treat every CI failure as either a product defect or a pipeline defect.
- When CI fails, fix the immediate cause and harden the system so that the same failure is easier to diagnose and less likely to recur.
- Do not hide flaky tests with broad retries. Find and remove the source of nondeterminism.
- A task is incomplete until all relevant local and CI-equivalent targets pass.

## Release tags and release notes

- Every release tag must include complete release notes describing all functionality differences from the previous release.
- Release notes must cover additions, behavior changes, bug fixes, removals, security changes, REST changes, MCP changes, proxy/TLS semantics, configuration/schema changes, deployment changes, compatibility impact, migrations, and known limitations.
- A raw commit list or automatically generated pull-request list is not sufficient.
- Breaking changes require explicit migration guidance and the version increment required by the compatibility policy.
- Release notes and changelog entries are part of the release artifact and must be reviewed before tagging.

## Documentation is mandatory

- All documentation must be kept up to date.
- Update affected architecture, API, MCP, configuration, security, operation, testing, deployment, task, and ADR documents in the same change as the implementation.
- Stale documentation is a defect and blocks task completion.
- Examples must be tested or generated where practical.
- Internal links, code samples, configuration examples, and command lines must pass documentation checks.
- Update `Last reviewed` metadata when a document receives a substantive review.
- Do not change an architectural invariant without an ADR.
- Cross-file links in README and `docs/` use absolute HTTPS URLs (`https://github.com/hilather/go-lab-mitmproxy/blob/main/...`).

## REST and MCP parity

- Every public REST control capability must have an MCP equivalent except rows marked `REST_ONLY_PROTOCOL`.
- Every state-changing MCP tool must have a REST equivalent.
- Parameterized MCP read tools must have REST equivalents; MCP resources may mirror REST GET representations.
- Both adapters must use the same input and output domain types and the same authorization decision.
- Every mutation must support validation, dry-run planning, optimistic concurrency, idempotency, actor identity, reason, deterministic errors, audit emission, and an atomic commit.
- Run parity verification whenever REST, MCP, schemas, authorization, or application commands change.

## Dial isolation and intercept correctness

- Dial idents are forbidden by default in every production `internal/*/*.go` except `internal/proxy`.
- `internal/tlsmitm` handshakes only; it must not Dial.
- Hostname-only target guards are insufficient; every resolved A/AAAA must pass CIDR guards.
- Handshake failure on an intercept-eligible CONNECT closes both sides; do not fall back to a blind tunnel.
- Never log or export a CA private key. `GET /v1/ca` is cert-only and authenticated.

## Generated files

- Do not manually edit generated OpenAPI, JSON Schema, MCP manifest, mocks, golden capability maps, or generated documentation.
- Change the source model or specification and run the documented generation target.
- Generation verification must leave the worktree clean.

## Dependencies

- Prefer the Go standard library and small, well-maintained libraries.
- Pin direct dependencies and review transitive changes.
- Allowed 1.0 direct deps: `gopkg.in/yaml.v3`, `github.com/modelcontextprotocol/go-sdk v1.7.0`, `github.com/oklog/ulid/v2`. 1.1 codec: `golang.org/x/net/http2` behind `internal/http2x` only.
- No Prometheus client (`github.com/prometheus/*` forbidden). Metrics are hand-rolled OpenMetrics.
- 1.1 allows `golang.org/x/net/http2` as a **codec** behind `internal/http2x` only (ADR 0009 / D28; Apache-2.0 compatible BSD-3). Still forbidden as a proxy/MITM framework. Production Dial idents stay forbidden in `internal/http2x`. `http2.Transport.DialTLS` stays nil; `DialTLSContext` may only return `proxy: intercepted CONNECT refuses redial` (never `tls.Dial`). New deps need a PR justification and license check (Apache-2.0 compatible).

## Required completion commands

The implementation repository should provide equivalent targets for:

```text
make format
make lint
make generate
make verify-generated
make test
make test-race
make test-fuzz-smoke
make test-parity
make test-config-compat
make test-docs
make test-container
make security-scan
make test-changelog
make web-test
make web-build
```

If a target does not yet exist, the task that first needs it must add it rather than silently omitting the check. Placeholders must fail closed, not succeed as no-ops.

CFG-001 required CI jobs: `format`, `lint`, `unit`, `documentation`, `config-compat`. API-001 adds `generated-file`. MCP-001 adds `parity` (`make test-parity`). DEP-001 adds `container-test`. UI-001 adds `web`. GA-001 adds `race`, `fuzz-smoke`, `security-scan`, `changelog`, and Release `tag-gate`.
