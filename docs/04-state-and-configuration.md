# State and Configuration

Status: Proposed normative behavior
Owners: Configuration, Application
Last reviewed: 2026-08-18 (design pack)
Related ADRs: 0003, 0012

Desired state is YAML. Flows are not. Config revision is a content hash of the canonical spec (secret **paths**, never values). Flow store has its own monotonic `storeGeneration`. Reset reloads YAML **and** wipes flows. The CA directory is a secret mount; reset does not rotate it.

## YAML bootstrap schema

One document. UTF-8. No aliases/anchors. No duplicate keys. No multi-doc streams. Max file size 1 MiB. Unknown fields are errors (`yaml.Decoder.KnownFields(true)`). Durations use Go syntax. Byte sizes use binary units via `config.ByteSize` (bare numbers rejected). Secret values are **file references** only. Keep `additionalProperties: false`.

```yaml
apiVersion: labmitm.dev/v1alpha1
kind: LabMITM
metadata:
  name: lab-proxy
spec:
  listeners:
    proxy:
      address: ":8080"
    socks:
      address: ""                 # empty = no extra SOCKS bind; use modes
    management:
      address: ":8081"
      restPath: /v1
      mcpPath: /mcp
      compatEnabled: true         # mitmweb routes
      tls:
        enabled: false
        certFile: ""
        keyFile: ""

  proxy:
    modes:
      - type: regular
        listen: ":8080"
    http2: true
    http3: false                  # true rejected in 1.0
    websocket: true
    rawtcp: false
    connectionStrategy: eager     # eager | lazy
    bodySizeLimit: 25MiB
    streamLargeBodies: ""
    storeStreamedBodies: false
    validateInboundHeaders: true
    normalizeOutboundHeaders: true
    http2PingKeepalive: 58s
    tcpTimeout: 600s
    blockGlobal: false            # lab overlay; mitmproxy default is true
    blockPrivate: false
    ignoreHosts: []
    allowHosts: []
    intercept:
      filter: ""
      active: false
    proxyauth:
      mode: off                   # off | basic | any
      username: ""
      passwordFile: ""
      dangerAllowAnyProxyAuth: false
    upstreamAuth:
      username: ""
      passwordFile: ""
    onboarding:
      enabled: true
      host: mitm.it
    reverse:
      keepHostHeader: false
      keepAltSvcHeader: false

  tls:
    confDir: /var/lib/labmitm/ca  # must contain mitmproxy-ca.pem layout or labmitm-ca.pem
    sslInsecure: false
    upstreamCert: true
    addUpstreamCertsToClientChain: false
    requestClientCert: false
    clientCerts: ""
    certs: []                     # [{ hosts: ["*.example.test"], certFile, keyFile }]
    keySize: 2048
    versionClientMin: TLS1_2
    versionClientMax: UNBOUNDED
    versionServerMin: TLS1_2
    versionServerMax: UNBOUNDED
    trustedCAFile: ""
    certPassphraseFile: ""

  store:
    maxFlows: 10000
    maxBytes: 512MiB
    maxInFlight: 256
    fullPolicy: evict_oldest      # reject | evict_oldest
    maxWait: 60s
    spillDirectory: ""
    spillThreshold: 1MiB

  addons:
    anticache: false
    anticomp: false
    stickyCookie: ""
    stickyAuth: ""
    modifyHeaders: []             # mitmproxy pattern strings
    modifyBody: []
    mapLocal: []
    mapRemote: []
    blockList: []
    scripts: []                   # Starlark paths inside the container, not .py
    serverReplay:
      files: []
      extra: forward
      ignoreContent: false
      ignoreHost: false
      ignorePort: false
      ignoreParams: []
      ignorePayloadParams: []
      useHeaders: []
      reuse: false
      refresh: true
    clientReplay:
      files: []
      concurrency: 1

  ui:
    enabled: true

  management:
    auth:
      mode: bearer                # bearer | bearer_and_basic | dev-loopback-unauth
      tokens:
        - id: admin
          secretFile: /run/secrets/labmitm-token
          role: administrator
          scopes: [mitm.read, mitm.write, mitm.admin, mitm.audit.read, mitm.script]
      basic:
        username: admin
        passwordFile: /run/secrets/labmitm-web-password
        tokenRef: admin
    mcp:
      allowLegacyClients: false
    originAllowlist: []
    bodyLimit: 8MiB
    requestsPerSecond: 32
    burst: 64
    maxConcurrent: 256

  observability:
    logLevel: info
    metrics:
      listen: "127.0.0.1:9090"
      publicPath: false
    audit:
      ring: 256
```

## Reserved / rejected keys (1.0)

Fail closed after normalize (strip dashes/underscores/case):

```
transparent, wireguard, tunmode, localcapture, scriptsPy, pythonPath,
mitmdump, mitmweb, confdirWrite, optionsSavePath
```

`http3: true`, `rawtcp: true`, mode types `transparent|local|wireguard|tun` → `validation_failed`.

`.py` entries in `addons.scripts` → `validation_failed` with remediation “use Starlark `.star` (ADR 0007)”.

## CA files

`spec.tls.confDir` must contain:

| File | Role |
|---|---|
| `labmitm-ca.pem` (preferred) or `mitmproxy-ca.pem` | CA cert + key PEM |
| `labmitm-ca-cert.pem` | Cert only, generated at CA create if missing |

Serve fail-closes if the CA file is missing or not a CA (`keyCertSign` + `CA:TRUE`). The process **never writes** this directory unless `labmitm ca generate` is invoked by an operator (not `serve`).

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

`drifted` is `runtimeRevision != bootstrapRevision` only (live option overlay / plan-apply). Flow insert does not set drifted.

## Plan / apply

Closed operation set (extend only with ADR + capability row):

| Op | Effect |
|---|---|
| `replaceModes` | Listener modes (may require rebind; 1.0 may reject live rebind and require reset) |
| `replaceIntercept` | filter + active |
| `replaceIgnoreHosts` | ignore/allow lists |
| `replaceModifyHeaders` | header transforms |
| `replaceModifyBody` | body transforms |
| `replaceMapLocal` | map local |
| `replaceMapRemote` | map remote |
| `replaceBlockList` | block list |
| `replaceAddonFlags` | anticache/anticomp/sticky* |
| `replaceStoreCaps` | store caps; shrink fail-closed if over new cap unless evict |
| `replaceTLSVerify` | `sslInsecure`, trusted CA (not CA rotation) |
| `setScripts` | load/unload Starlark (`mitm.script`) |

Live **rebind** of proxy listen address in 1.0: **rejected** (`validation_failed`, remediation: change YAML and reset). Intercept and transforms apply live.

`changes.apply` requires `expectedRevision`. Idempotency-Key supported.

## Reset

`state.reset`:

1. Re-read bootstrap YAML (fail → keep previous snapshot, error).
2. Re-read token and CA files.
3. Wipe flow store and spill.
4. Unload scripts and reload from spec.
5. Do not rotate CA keys.
6. Bump generation; `storeGeneration` resets to 0 then wipe bumps as specified by STORE-001 tests (frozen: wipe sets `storeGeneration` to previous+1 then contents empty, or to 1; **choose previous+1** so waiters wake).

## Related documents

- Architecture D3: [docs/01-architecture.md](01-architecture.md)
- REST plan/apply: [docs/06-rest-api.md](06-rest-api.md)
