import type { StateView, Status, StatusFeatures } from "../api/types";

export function sampleStatusFeatures(overrides: Partial<StatusFeatures> = {}): StatusFeatures {
  return {
    http2: false,
    http2ClientCleartext: false,
    http2Origin: false,
    http2ExtendedConnect: false,
    http2CapturePush: false,
    http2GRPCDecode: false,
    inspectWebSocketFrames: false,
    socks5: false,
    socks4: false,
    acceptBind: false,
    acceptUDPAssociate: false,
    acceptUserPass: false,
    originalDestination: false,
    compatFlowREST: false,
    httpAuth: false,
    ...overrides,
  };
}

export function sampleStatus(overrides: Partial<Status> = {}): Status {
  return {
    ready: true,
    intercept: true,
    revisions: { runtime: "abc" },
    listeners: [{ name: "proxy", address: "127.0.0.1:8888" }],
    store: { flowCount: 1, storeBytes: 12, storeGeneration: 3, epoch: 1 },
    ca: {
      mode: "generate",
      spkiSha256: "deadbeef",
      subject: "CN=LabMITM",
      notAfter: "2099-01-01T00:00:00Z",
    },
    features: sampleStatusFeatures(),
    ...overrides,
  };
}

export function sampleState(runtimeRevision = "sha256:abc", ports: number[] = [443]): StateView {
  return {
    runtimeRevision,
    bootstrapRevision: "sha256:boot",
    generation: 4,
    drifted: false,
    canonical: {
      spec: {
        tls: {
          intercept: true,
          hosts: [],
          ports,
          ca: { mode: "generate", certFile: "", keyFile: "" },
          upstream: { insecureSkipVerify: false, extraCAFiles: [] },
        },
        rules: { enabled: false, items: [] },
        compat: { flowREST: { enabled: false, pathPrefix: "/compat" } },
        listeners: {
          originalDestination: { enabled: false, address: "" },
          proxy: { address: "127.0.0.1:8888" },
          management: { address: "127.0.0.1:8088" },
        },
        proxy: {
          admission: {
            maxSessions: 256,
            maxSessionsPerIP: 32,
            maxInFlight: 64,
            maxInFlightBytes: "64MiB",
            sessionTimeout: "10m",
            idleTimeout: "120s",
            headerTimeout: "10s",
            dialTimeout: "10s",
            upstreamTimeout: "60s",
            maxConcurrentStreams: 100,
          },
          httpAuth: { enabled: false, realm: "labmitm-proxy", users: [] },
        },
        observability: { metrics: { listen: "127.0.0.1:9090" } },
      },
    },
  };
}

export function portsOnlyState(runtimeRevision = "sha256:abc", ports: number[] = [8443]): StateView {
  return {
    runtimeRevision,
    canonical: {
      spec: {
        tls: {
          intercept: true,
          hosts: [],
          ports,
          ca: { mode: "generate", certFile: "", keyFile: "" },
          upstream: { insecureSkipVerify: false, extraCAFiles: [] },
        },
      },
    },
  };
}
