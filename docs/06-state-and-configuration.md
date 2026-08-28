# State and Configuration

Status: Proposed normative behavior
Owners: Configuration, Application
Last reviewed: 2026-08-28 (D75 action.bytesPerSecond)
Related ADRs: 0003, 0008, 0012, 0013, 0014, 0015, 0016

Desired state is YAML. The flow store is not. Config revision is a content hash of the canonical spec. Flow store has its own monotonic `storeGeneration`. Reset reloads YAML **and** wipes flows. See [docs/adr/0003-ephemeral-flows-and-gitops.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0003-ephemeral-flows-and-gitops.md).

STA-001 implements the HTTP-less control plane: `internal/compiler` (the **only** compiler), `internal/snapshot` (atomic immutable snapshot), `internal/audit` (ring + redact), and `internal/app.Service` (`Plan` / `Apply` / `Reset` / `Export`). API-001 REST (`internal/control/rest`) and MCP-001 (`internal/control/mcp`) call `app.Service` rather than reimplementing mutation.

## YAML rules (fail-closed)

- One document. UTF-8. No aliases/anchors. No duplicate keys. No multi-doc streams.
- Max file size 1 MiB.
- Unknown fields are errors (`yaml.Decoder.KnownFields(true)`).
- Durations: Go syntax (`30s`, `5m`).
- Byte sizes: binary units via `config.ByteSize` (`10MiB`, `256KiB`); bare numbers rejected.
- Secrets are **file references** only. Reject `environment:` as unknown. No `LABMITM_ALLOW_ENV_SECRETS`.
- `additionalProperties: false` in published JSON Schema.

Reserved / rejected keys (normalize strips dashes/underscores/case before compare):

```
socks, socks5, socks4, tproxy, transparent, reverseproxy, reverse_proxy,
publicca, trustedroot, mitmproxyaddon, addon, pythonaddon, exploit,
payloadgen, attack, sslstrip, hstsstrip
```

Plus any key that would imply wrapping the Python binary (`mitmproxy`, `mitmdump`, `mitmweb` as config sections). Reserved keys are **not a LabMITM surface** (D41). Legal names are camelCase only (`acceptSOCKS5` / `acceptBind` are legal; `accept-socks5` / `accept-bind` fail KnownFields; `spec.socks` / `socksBind` / `socksUserPass` / `spec.compat.mitmproxyREST` stay reserved).

## Bootstrap schema (v1alpha1; 1.1 opt-in and 1.2 fields default off; D22 carve)

```yaml
apiVersion: labmitm.dev/v1alpha1
kind: LabMITM
metadata:
  name: lab-proxy
spec:
  listeners:
    proxy:
      address: "127.0.0.1:8888"
      acceptSOCKS5: false          # 1.1; live setFeature (D51')
      acceptSOCKS4: false          # 1.1; live setFeature (D51')
      acceptBind: false            # 1.2; Reset-only; requires acceptSOCKS5 or acceptSOCKS4
      acceptUDPAssociate: false    # 1.2; Reset-only; requires acceptSOCKS5
      acceptUserPass: false        # 1.2; Reset-only; requires acceptSOCKS5 and ≥1 user
      userPass:
        users: []
    originalDestination:           # 1.1; Reset-only bind (D51')
      enabled: false
      address: ""                  # empty + enabled → 127.0.0.1:8890
    management:
      address: "127.0.0.1:8088"
      restPath: /v1
      mcpPath: /mcp
      tls:
        enabled: false
        certFile: ""
        keyFile: ""

  proxy:
    hostname: labmitm.lab
    admission:
      maxSessions: 256
      maxSessionsPerIP: 32
      maxInFlight: 64
      maxInFlightBytes: 64MiB
      sessionTimeout: 10m
      idleTimeout: 120s
      headerTimeout: 10s
      dialTimeout: 10s
      upstreamTimeout: 60s
      maxConcurrentStreams: 100    # 1.1; 0 → 100; live via replaceAdmission
    targets:
      denyCloudMetadata: true
      denyLinkLocal: true
      allowLoopback: true
      allowHosts: []
      denyHosts: []

  tls:
    intercept: false
    hosts: []
    ports: [443]
    ca:
      mode: generate
      certFile: ""
      keyFile: ""
    upstream:
      insecureSkipVerify: false
      extraCAFiles: []

  rules:
    enabled: false
    items: []

  store:
    maxFlows: 1000
    maxBytes: 256MiB
    maxBodyBytes: 1MiB
    fullPolicy: reject
    maxWait: 60s
    spillDirectory: ""
    spillThreshold: 256KiB

  ui:
    enabled: true

  management:
    auth:
      mode: bearer
      tokens:
        - id: admin
          secretFile: /run/secrets/labmitm-token
          role: administrator
          scopes: [mitm.read, mitm.write, mitm.admin, mitm.audit.read]
    mcp:
      allowLegacyClients: false
    originAllowlist: []
    bodyLimit: 1MiB
    requestsPerSecond: 32
    burst: 64
    maxConcurrent: 256

  observability:
    logLevel: info
    metrics:
      listen: "127.0.0.1:9090"
      publicPath: false
    audit:
      ring: 128

  protocols:                       # hop gates live-applyable via setFeature (ADR 0013)
    http2:
      enabled: false               # 1.1; default off (D22); live next CONNECT
      clientCleartext: false
      origin: false
      extendedConnect: false
      capturePush: false
      grpcDecode: false
    websocket:
      enabled: true                # D22 carve default on (ADR 0013); live; off is 403 before rules/Dial
      inspectFrames: false         # 1.2; Reset-only
    connect:
      enabled: true                # D22 carve default on (ADR 0013); live; off is 403 before Hijack
    absoluteForm:
      enabled: true                # D22 carve default on (ADR 0013); live; off is 403 before DNS

  compat:                          # 1.1; live setFeature / replaceCompat (D51'); no /compat on catalog() / native compileRoutes
    flowREST:
      enabled: false
      pathPrefix: /compat          # validated against configured restPath/mcpPath
```

Empty `spec: {}` is valid and materializes the standalone loopback defaults (`127.0.0.1:8888` / `127.0.0.1:8088`). 1.1 opt-in and 1.2 fields materialize **false**. Omitted `protocols.websocket` / `connect` / `absoluteForm` (including present-but-null maps) materialize `enabled: true` at decode (D22 carve, [ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md)) so hop behavior stays 1.0 (HTTP/1.1 + SOCKS-close + WebSocket 101). Canonicalize of today’s empty spec **grows** those three enabled objects. Disabled gates 403 `forbidden` before rules/Dial (websocket on both `serveAbsolute` and `serveOrigDestHTTP`; CONNECT after orig-dest D57 before Hijack; absolute-form only on `serveAbsolute`). `labmitm validate --config` and `labmitm canonicalize --config [--format yaml|json]` implement this loader. `labmitm serve` (PROXY-001) binds the proxy after a successful load; invalid bootstrap binds nothing.

The published schema is [api/jsonschema/labmitm.dev.v1alpha1.json](https://github.com/hilather/go-lab-mitmproxy/blob/main/api/jsonschema/labmitm.dev.v1alpha1.json). `tls.upstream.verify` is not an input field; the only upstream verify knob is `insecureSkipVerify`. Export / `GET /v1/status` (later) materializes read-only `verify: !insecureSkipVerify`.

## Validate rules (fail closed)

- `listeners.proxy.address` and `listeners.management.address` (and `metrics.listen` when non-empty) must parse as `host:port` via `net.SplitHostPort` with port `1–65535`. Validate is offline (no DNS). `:8888` and `[::1]:8088` are legal. Empty listener address materializes the loopback defaults first, **not** `:8888`.
- Standalone defaults materialize to loopback (D10).
- `tls.ca.mode: files` requires existing cert+key; reject empty key PEM; reject world-writable key file; `mode: generate` with non-empty cert/key files → `validation_failed`.
- The only upstream input field is `insecureSkipVerify`. `tls.upstream.verify` is **not** on the struct.
- `tls.ports` entries are `1–65535`. After normalize, empty → `[443]`.
- `tls.intercept: true` with `ca.mode: files` and unreadable key → validate fail (do not bind).
- `rules.items[].id` unique and `[a-z0-9-]{1,64}`. Every item requires `phase` (`request`|`response`|`websocket`) and `action.type` (`breakpoint` \| `drop` \| `delay` \| `status` \| `header` \| `body` \| `silent` \| `hang` \| `redirect` \| `block` \| `throttle`). `phase: websocket` allows only `drop` or `block`. `block` is illegal on `request|response`. `throttle` is illegal on `websocket`. Non-empty `match.opcode` / `direction` / `payloadContains` on `request|response` is `validation_failed`. `action.delay` ∈ [0, 30s]. When `type=throttle`, `action.bytesPerSecond` ∈ [256B, 64MiB] (IEC YAML; REST apply JSON is IEC; MCP apply JSON is integer bytes). Other types ignore `bytesPerSecond`. `action.status` empty or 400–599. Body replace ≤ 64 KiB in YAML. `hang.timeout` required and ∈ [1s, 30s]. `redirect.location` required (≤2048 bytes; no CR/LF/NUL). `redirect.status` empty or 301/302/303/307/308. `silent.close` / `hang.close` empty, `rst`, or `fin`. `http_status` is not a legal type.
- `store.maxBodyBytes` ≥ 1 KiB and ≤ `store.maxBytes`. `maxFlows` ≥ 1. `maxBytes` ≥ 1 MiB.
- Loader: `management.auth.mode: bearer` with **zero tokens is valid** (empty `spec: {}` must load). Each listed token requires `id`, `secretFile`, and `role`. Overlay `secretFile` paths that are not mounted do not fail validate; if the file exists, the first non-comment line must be ≥32 bytes (256 bits) after trim. `scopes` materialize to `[]` when omitted.
- Serve/bind (SEC-001): binding management with `mode: bearer` and zero usable tokens is **refused**. `dev-loopback-unauth` is rejected in the container default fixture (`testdata/container/config.yaml` is `mode: bearer`). Keep ADR 0005’s listen-refuse sentence as serve-time. Token files are reread on reset and apply.
- `acceptBind: true` requires `acceptSOCKS5` or `acceptSOCKS4`. `acceptUDPAssociate: true` and `acceptUserPass: true` require `acceptSOCKS5`. `acceptUserPass: true` also requires ≥1 `userPass.users[]` entry. User `id` is unique `[a-z0-9-]{1,64}`; `usernameFile` / `passwordFile` must exist at **Start/Reset** and the first non-comment line must be 1–255 bytes (RFC 1929). File refs only — no inline username/password. Users present while `acceptUserPass` is false are still validated at load. Live apply copies compiled digests and does not reread the files.
- `protocols.http2.origin: true` requires `http2.enabled`. `extendedConnect: true` requires `http2.enabled` or `clientCleartext`. `capturePush: true` requires `origin`. `grpcDecode: true` requires `http2.enabled` or `origin`. Empty `spec: {}` materializes every 1.2 flag **false**.

## Revisions

```json
{
  "bootstrapRevision": "sha256:…",
  "runtimeRevision": "sha256:…",
  "generation": 4,
  "storeGeneration": 18,
  "drifted": false,
  "flowCount": 3,
  "storeBytes": 4096,
  "loadedAt": "2026-08-18T00:00:00Z"
}
```

- Revisions: SHA-256 of canonical normalized spec (secrets as reference paths, never values; generated CA material is **not** in the spec hash).
- `generation`: process-local config swap counter.
- `storeGeneration`: insert/delete/wipe/evict/breakpoint-state only.
- `drifted`: `runtimeRevision != bootstrapRevision`. Flows do **not** set `drifted`.

## Reset

`POST /v1/state:reset` / `mitm_state_reset`:

1. Re-read bootstrap path (never write it).
2. Validate + compile. On failure, leave current config **and** flows unchanged.
3. Preflight store options and CA load/generate.
4. `store.ResetTo` — the only epoch bump.
5. Atomically swap snapshot, clear idempotency LRU, increment `generation`.
6. In-flight proxy sessions keep the old snapshot until the request ends; new accepts load the new one.
7. Audit `state.reset`.

Restart is equivalent: process memory dies; generate-mode CA is new; spill wiped on next start.

## Plan / apply operations

```json
{
  "expectedRevision": "sha256:…",
  "idempotencyKey": "01J…",
  "reason": "enable login breakpoint",
  "force": false,
  "operations": [
    {
      "op": "replaceRules",
      "rules": { "enabled": true, "items": [] }
    }
  ]
}
```

| `op` | Body | Notes |
|---|---|---|
| `replaceStoreCaps` | `store`: `{maxFlows, maxBytes, maxBodyBytes, fullPolicy}` | Shrink + `reject` fails unless `force` |
| `replaceAdmission` | `admission` object | Live on next accept for the session gate, CONNECT dial timeout, and pinned tunnel idle/session deadlines. `http.Server.IdleTimeout` / `ReadHeaderTimeout` and the process-wide cleartext `Transport` stay at Start (`Options.Spec`). |
| `replaceTLS` | `tls` object | Recompile CA/host list; in-flight CONNECT unchanged |
| `replaceRules` | `rules` object | `{}` / empty items + `enabled: false` is stock capture |
| `replaceTargets` | `targets` object | Live on next request |
| `replaceCompat` | `compat` object (`enabled` + `pathPrefix`) | Live on next management request. Prefix collision with restPath/mcpPath is `validation_failed`. |
| `setFeature` | `feature`: `{id, enabled}` | Closed IDs: `protocols.http2`, `protocols.websocket`, `protocols.connect`, `protocols.absoluteForm`, `listeners.proxy.acceptSOCKS5`/`acceptSOCKS4`, `compat.flowREST` (enabled only), `rules.enabled` (items unchanged), `ui.enabled`. Rejects `listeners.originalDestination` (Reset-only) and `tls.intercept` (use `replaceTLS`). Plan warns `live_next_connection`. |

`:plan` is dry-run. `:apply` requires `expectedRevision`. Idempotency: key + identity (`reason` + canonical operations). Failures not cached. `revision_conflict` → 409. Listener **addresses** are not live-applyable; change YAML and reset. Plan of `setFeature` / `replaceCompat` warns `live_next_connection` (in-flight sessions keep the snapshot they pinned; SOCKS peek and new ServeHTTP/CONNECT see the swap). The only other Apply warning is `store_evict`.

**D22 carve:** 1.1 **opt-in** flags stay default-off (`http2`, `acceptSOCKS5`/`acceptSOCKS4`, `originalDestination`, `compat.flowREST`). 1.2 nested flags stay default-off. Gates whose Go zero would **change 1.0 hop behavior** (`protocols.websocket` / `connect` / `absoluteForm`) default **on** at `applyDecodeDefaults`. `ui.enabled` remains the 1.0 D13 true default. Do not tell operators “all new fields default off” and also ship default-true hop gates.

### 1.1 / 1.2 flags (D51' live hop/accept vs Reset bind)

[ADR 0013](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/adr/0013-live-protocol-feature-gates.md) replaces D51. `setFeature` is the only protocol/accept mutation. Plus `replaceCompat` (enabled **and** `pathPrefix`). No `replaceProtocols` / `replaceProxyAccept`. `setFeature` of `tls.intercept` is `validation_failed` (use `replaceTLS`). `setFeature` of Reset-only IDs is `validation_failed` with remediation “edit bootstrap YAML and Reset”. `setFeature` / `replaceCompat` are on `KnownOp`. Websocket/connect/absoluteForm are live hop 403s (`Error=forbidden`; metric reasons `websocket`, `connect`, `absolute_form`).

| Field | How to change |
|---|---|
| `acceptSOCKS5` / `acceptSOCKS4` | **live** `setFeature` (next peek) |
| `protocols.http2.enabled` | **live** `setFeature` (next CONNECT) |
| `protocols.websocket.enabled` / `connect.enabled` / `absoluteForm.enabled` | **live** `setFeature` (default **on**, D22 carve). Off is 403 before rules/Dial; inner websocket 403 keeps CONNECT |
| `compat.flowREST.enabled` | **live** `setFeature` (next management request) |
| `compat.flowREST.pathPrefix` | **live** `replaceCompat` only (not `setFeature`) |
| `rules.enabled` | **live** `setFeature` (items unchanged) |
| `ui.enabled` | **live** `setFeature` from REST/MCP only — **no Status toggle** |
| `tls.intercept` | **live** `replaceTLS` (generate-mode CA rotates when the TLS spec changes) |
| `acceptBind` / `acceptUDPAssociate` / `acceptUserPass` | Reset-only (1.2; no `replaceProxyAccept`) |
| `listeners.originalDestination` enabled+address | Reset-only (bind) |
| `protocols.http2.clientCleartext` / `origin` / `extendedConnect` / `capturePush` / `grpcDecode` | Reset-only (1.2) |
| `protocols.websocket.inspectFrames` | Reset-only (1.2) |
| `proxy.admission.maxConcurrentStreams` | **`replaceAdmission`**. New TCP sessions only |
| Listener **addresses**, management TLS files, `metrics.listen` | Reset-only (unchanged) |

Operator residual (same split): [docs/known-limitations.md](https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/known-limitations.md#live-hopaccept-vs-reset-bind-d51-operator-residual).

Idempotency LRU default 256; reset clears it.

## Compiler, snapshot, and `app.Service`

`internal/compiler.Compile` is the only spec → snapshot path. It:

1. `config.Normalize` + `config.Validate` (copy-on-write).
2. Hashes canonical JSON (`sha256:…`). Generated CA material is **not** in the hash.
3. Builds `rules.Engine` from `spec.rules`.
4. Generates or loads the lab CA (`tlsmitm.Authority`). Generate-mode mints even when `intercept: false` so `GetCA` works. `replaceRules` / `replaceAdmission` / `replaceTargets` / `replaceStoreCaps` / `setFeature` / `replaceCompat` reuse the previous CA handle when the TLS spec is unchanged. `replaceTLS` and `Reset` recompile (generate-mode rotates).
5. Loads SOCKS user-pass digests into snapshot side table `SOCKSUsers` (not Canonical, not export) only when `Previous == nil` (Start/Reset). Live Compile copies `Previous.SOCKSUsers` and does **not** stat password files (D60). Do not key that copy off TLS equality.

`internal/snapshot.Store` holds active / previous / bootstrap behind atomic pointers. The proxy loads once per request / CONNECT (`Options.Snapshots`) and pins spec, engine, CA, and store epoch for the session. In-flight sessions keep the pointer they loaded; new accepts see the swapped snapshot. An in-flight `Insert` after `ResetTo` uses the accept-time epoch and is discarded (`ErrStaleEpoch`).

`internal/app.Service` is HTTP-less (no `net/http`, no MCP types, no Dial). Mutations copy Canonical, apply typed operations, compile a full candidate, then `Store.Swap` only after success. Failures leave config **and** flows unchanged. Reset rereads the bootstrap path, preflights store options (including spill), `store.ResetTo` (the only epoch bump), swaps, and clears the idempotency LRU.

`internal/audit` is a bounded ring (default 128) plus optional hook. Secrets, bearer tokens, and PEM private keys (`BEGIN` + `PRIVATE`) are redacted. Hook delivery failure is counted and never fail-closes.

## Startup

```text
read file
 -> reject unknown fields and reserved names
 -> decode versioned schema
 -> normalize names, durations, byte sizes, defaults
 -> validate cross-references and policy constraints
 -> compile snapshot (rules index; CA generate or load)
 -> compute bootstrap and runtime revisions
 -> wipe configured spill path
 -> bind proxy then management
 -> write pid file
```

A failed validate/compile exits non-zero and binds nothing.

Shutdown: `Accepting()=false` (ready goes unready) → drain in-flight proxy sessions up to `--shutdown-timeout` → close management → wipe spill → exit.

## Compatibility promise

`labmitm.dev/v1alpha1` is fail-closed; additive fields only after schema bump or explicit defaulting ADR.
