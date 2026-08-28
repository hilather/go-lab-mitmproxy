import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CSRF_HEADER } from "../api/client";
import type { Feature, FeatureList } from "../api/types";
import { json, renderApp, resetClientState, sessionView } from "../test/render";
import { FORBIDDEN_CONTROL_LABELS } from "../ui/forbidden";
import { StatusPage } from "./StatusPage";

function sampleStatus() {
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
    features: {
      http2: false,
      socks5: false,
      socks4: false,
      originalDestination: false,
      compatFlowREST: false,
    },
  };
}

function feature(
  id: string,
  enabled: boolean,
  applyMode: string,
  verb: string,
  description: string,
): Feature {
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

function sampleFeatures(revision = "sha256:abc"): FeatureList {
  return {
    runtimeRevision: revision,
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
}

function notFound(): Response {
  return json(404, {
    status: 404,
    title: "not found",
    detail: "not found",
    code: "not_found",
    type: "urn:labmitm:error:not-found",
  });
}

function stubPageFetch(opts?: {
  scopes?: string[];
  features?: FeatureList;
  apply?: (body: string, init?: RequestInit) => Promise<Response> | Response;
}) {
  const catalog = opts?.features ?? sampleFeatures();
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    if (url.endsWith("/v1/session")) {
      return json(200, sessionView(opts?.scopes));
    }
    if (url.endsWith("/v1/status")) {
      return json(200, sampleStatus());
    }
    if (url.endsWith("/v1/features") && method === "GET") {
      return json(200, catalog);
    }
    if (url.endsWith("/v1/changes:apply") && method === "POST") {
      if (opts?.apply) {
        return await opts.apply(String(init?.body ?? ""), init);
      }
      return json(200, { applied: true, runtimeRevision: "sha256:next" });
    }
    return notFound();
  });
  vi.stubGlobal("fetch", fetchMock);
  return { fetchMock, catalog };
}

describe("StatusPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("shows ca.spkiSha256 and a cert-only CA download", async () => {
    stubPageFetch();
    renderApp(<StatusPage />, { route: "/status" });
    expect(await screen.findByText("deadbeef")).toBeInTheDocument();
    expect(screen.getByText("generate")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /Download lab CA certificate/i });
    expect(link).toHaveAttribute("href", "/v1/ca");
    expect(screen.getByText(/private key is never exported/i)).toBeInTheDocument();
    expect(screen.getByText(/Lab-only intercepting proxy/i)).toBeInTheDocument();
  });

  it("renders the feature catalog with on/off and live/reset", async () => {
    stubPageFetch();
    renderApp(<StatusPage />, { route: "/status" });
    expect(await screen.findByRole("heading", { name: "Features" })).toBeInTheDocument();
    expect(screen.getByText("protocols.websocket")).toBeInTheDocument();
    expect(screen.getByText("listeners.originalDestination")).toBeInTheDocument();
    expect(screen.getByText("ui.enabled")).toBeInTheDocument();
    expect(screen.getAllByText("on").length).toBeGreaterThan(0);
    expect(screen.getAllByText("off").length).toBeGreaterThan(0);
    expect(screen.getAllByText("live").length).toBeGreaterThan(0);
    expect(screen.getByText("reset")).toBeInTheDocument();
    const reset = screen.getByRole("link", { name: /Reset required/i });
    expect(reset).toHaveAttribute("href", "/reset");
  });

  it("does not offer a Status toggle for ui.enabled or tls.intercept", async () => {
    stubPageFetch();
    renderApp(<StatusPage />, { route: "/status" });
    expect(await screen.findByRole("switch", { name: "Toggle protocols.websocket" })).toBeInTheDocument();
    expect(screen.queryByRole("switch", { name: "Toggle ui.enabled" })).toBeNull();
    expect(screen.queryByRole("switch", { name: "Toggle tls.intercept" })).toBeNull();
    expect(screen.getByText(/change via REST\/MCP/)).toBeInTheDocument();
    expect(screen.getByText("setFeature")).toBeInTheDocument();
  });

  it("hides toggles from viewers", async () => {
    stubPageFetch({ scopes: ["mitm.read"] });
    renderApp(<StatusPage />, { route: "/status" });
    expect(await screen.findByText("protocols.websocket")).toBeInTheDocument();
    expect(screen.queryByRole("switch")).toBeNull();
    expect(screen.queryByLabelText(/Reason/i)).toBeNull();
  });

  it("has no exploit or SSL-strip labels", async () => {
    stubPageFetch();
    renderApp(<StatusPage />, { route: "/status" });
    expect(await screen.findByRole("heading", { name: "Features" })).toBeInTheDocument();
    for (const label of FORBIDDEN_CONTROL_LABELS) {
      expect(screen.queryByText(label, { exact: true })).toBeNull();
    }
    expect(screen.queryByRole("button", { name: /fuzzer|repeater|exploit|relay|ssl-strip/i })).toBeNull();
  });

  it("posts setFeature through apiFetch and disables the control while in flight", async () => {
    const user = userEvent.setup();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const catalog = sampleFeatures();
    const { fetchMock } = stubPageFetch({
      features: catalog,
      apply: async (body) => {
        await gate;
        const parsed = JSON.parse(body) as {
          expectedRevision: string;
          idempotencyKey: string;
          operations: { op: string; feature: { id: string; enabled: boolean } }[];
        };
        const patch = parsed.operations[0]?.feature;
        const row = catalog.items.find((item) => item.id === patch?.id);
        if (row && patch) {
          row.enabled = patch.enabled;
        }
        catalog.runtimeRevision = "sha256:next";
        return json(200, { applied: true, runtimeRevision: "sha256:next" });
      },
    });
    vi.spyOn(crypto, "randomUUID").mockReturnValue("11111111-1111-4111-8111-111111111111");

    renderApp(<StatusPage />, { route: "/status" });
    const toggle = await screen.findByRole("switch", { name: "Toggle protocols.websocket" });
    expect(toggle).toBeChecked();
    await user.click(toggle);
    await waitFor(() => expect(toggle).toBeDisabled());
    expect(screen.getByRole("switch", { name: "Toggle protocols.http2" })).toBeDisabled();
    release();
    await waitFor(() => expect(toggle).toBeEnabled());
    await waitFor(() => expect(toggle).not.toBeChecked());

    const applyCall = fetchMock.mock.calls.find((c) => String(c[0]).endsWith("/v1/changes:apply"));
    expect(applyCall).toBeDefined();
    const init = applyCall?.[1];
    expect(new Headers(init?.headers).get(CSRF_HEADER)).toBe("csrf-test");
    expect(new Headers(init?.headers).get("Content-Type")).toBe("application/json");
    const sent = JSON.parse(String(init?.body ?? "")) as {
      expectedRevision: string;
      idempotencyKey: string;
      reason: string;
      operations: { op: string; feature: { id: string; enabled: boolean } }[];
    };
    expect(sent.expectedRevision).toBe("sha256:abc");
    expect(sent.idempotencyKey).toBe("11111111-1111-4111-8111-111111111111");
    expect(sent.reason).toBe("");
    expect(sent.operations).toEqual([
      { op: "setFeature", feature: { id: "protocols.websocket", enabled: false } },
    ]);
  });

  it("surfaces 409 detail, refetches, and does not reuse the idempotency key", async () => {
    const user = userEvent.setup();
    const keys = [
      "11111111-1111-4111-8111-111111111111",
      "22222222-2222-4222-8222-222222222222",
    ] as const;
    let keyN = 0;
    vi.spyOn(crypto, "randomUUID").mockImplementation(
      () => keys[keyN++] ?? "33333333-3333-4333-8333-333333333333",
    );
    let featureGets = 0;
    const applyBodies: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/status")) {
          return json(200, sampleStatus());
        }
        if (url.endsWith("/v1/features") && method === "GET") {
          featureGets += 1;
          return json(200, sampleFeatures(featureGets === 1 ? "sha256:abc" : "sha256:newer"));
        }
        if (url.endsWith("/v1/changes:apply") && method === "POST") {
          applyBodies.push(String(init?.body ?? ""));
          return json(409, {
            status: 409,
            title: "conflict",
            detail: "revision has changed",
            code: "revision_conflict",
            type: "urn:labmitm:error:revision-conflict",
          });
        }
        return notFound();
      }),
    );

    renderApp(<StatusPage />, { route: "/status" });
    const toggle = await screen.findByRole("switch", { name: "Toggle protocols.http2" });
    await user.click(toggle);
    expect(await screen.findByRole("alert")).toHaveTextContent("revision has changed");
    await waitFor(() => expect(toggle).toBeEnabled());
    await waitFor(() => expect(featureGets).toBeGreaterThan(1));
    expect(applyBodies).toHaveLength(1);
    expect(JSON.parse(applyBodies[0] ?? "").idempotencyKey).toBe(
      "11111111-1111-4111-8111-111111111111",
    );
    expect(JSON.parse(applyBodies[0] ?? "").expectedRevision).toBe("sha256:abc");

    await user.click(toggle);
    await waitFor(() => expect(applyBodies).toHaveLength(2));
    expect(JSON.parse(applyBodies[1] ?? "").idempotencyKey).toBe(
      "22222222-2222-4222-8222-222222222222",
    );
    expect(JSON.parse(applyBodies[1] ?? "").expectedRevision).toBe("sha256:newer");
  });
});
