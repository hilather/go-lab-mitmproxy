import { createRoot } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { AppRoutes } from "../src/App";
import { AuthProvider } from "../src/auth/AuthProvider";
import type { Feature, FeatureList } from "../src/api/types";
import { sampleState, sampleStatus } from "../src/test/state";
import "../src/styles.css";

declare global {
  interface Window {
    __applyCalls: number;
    __planCalls: number;
  }
}

window.__applyCalls = 0;
window.__planCalls = 0;

const session = {
  id: "admin",
  role: "administrator",
  scopes: ["mitm.read", "mitm.write", "mitm.admin", "mitm.audit.read"],
  csrf: "csrf-harness",
  expiresAt: "2099-01-01T00:00:00Z",
};

function feature(id: string, enabled: boolean, applyMode: string, verb: string, description: string): Feature {
  return {
    id,
    yamlPath: `spec.${id}`,
    title: id,
    description,
    enabled,
    applyMode,
    verb,
  };
}

const features: FeatureList = {
  runtimeRevision: "sha256:abc",
  generation: 4,
  drifted: false,
  items: [
    feature("protocols.http2", false, "live", "setFeature", "Inner+origin ALPN h2"),
    feature("protocols.websocket", true, "live", "setFeature", "HTTP/1.1 Upgrade: websocket"),
    feature("protocols.connect", true, "live", "setFeature", "Forward-proxy HTTP CONNECT"),
    feature("protocols.absoluteForm", true, "live", "setFeature", "Absolute-form HTTP"),
    feature("listeners.proxy.acceptSOCKS5", false, "live", "setFeature", "SOCKS5 CONNECT"),
    feature("listeners.proxy.acceptSOCKS4", false, "live", "setFeature", "SOCKS4 CONNECT"),
    feature("listeners.originalDestination", false, "reset", "reset", "Linux SO_ORIGINAL_DST listener"),
    feature("compat.flowREST", false, "live", "setFeature", "Optional /compat adapter"),
    feature("tls.intercept", false, "live", "replaceTLS", "MITM intercept via replaceTLS"),
    feature("rules.enabled", false, "live", "setFeature", "Rules engine master switch"),
    feature("ui.enabled", true, "live", "setFeature", "Serves the flow-inspector SPA"),
  ],
};

const plan = {
  previousRevision: "sha256:abc",
  candidateRevision: "sha256:next",
  drifted: false,
  diff: [],
  warnings: [],
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  const method = (init?.method ?? "GET").toUpperCase();
  if (url.includes("/v1/session")) return json(200, session);
  if (url.includes("/v1/status")) return json(200, sampleStatus());
  if (url.includes("/v1/state") && method === "GET") return json(200, sampleState("sha256:abc"));
  if (url.includes("/v1/features") && method === "GET") return json(200, features);
  if (url.includes("/v1/changes:plan")) {
    window.__planCalls += 1;
    return json(200, plan);
  }
  if (url.includes("/v1/changes:apply")) {
    window.__applyCalls += 1;
    return json(200, { applied: true, runtimeRevision: "sha256:next" });
  }
  return json(404, { title: "not found", status: 404 });
};

createRoot(document.getElementById("root")!).render(
  <MemoryRouter initialEntries={["/status"]}>
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  </MemoryRouter>,
);
