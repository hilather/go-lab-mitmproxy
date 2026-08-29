import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../App";
import { json, renderApp, resetClientState, sessionView } from "../test/render";

const httpFlow = {
  id: "01JH2LIST",
  startedAt: "2026-08-18T00:00:00Z",
  state: "completed",
  method: "GET",
  url: "https://app.lab.test/login",
  host: "app.lab.test",
  scheme: "https",
  protocol: "h2",
  status: 200,
  intercepted: true,
  truncated: false,
  requestBytes: 0,
  responseBytes: 12,
  via: "original-dest",
  originalDest: "192.0.2.10:443",
  http2: { streamId: 7 },
  socks: { dest: "app.lab.test:443" },
  timings: { dnsMs: 0, connectMs: 1, tlsMs: 2, ttfbMs: 3, totalMs: 4 },
  request: {
    headers: [{ name: "Host", value: "app.lab.test" }],
    size: 0,
    truncated: false,
  },
  response: { size: 12, truncated: false },
};

const connectFlow = {
  id: "01JCONN",
  startedAt: "2026-08-18T00:00:01Z",
  state: "completed",
  method: "CONNECT",
  url: "",
  host: "directory",
  scheme: "",
  protocol: "connect",
  status: 200,
  intercepted: false,
  truncated: false,
  requestBytes: 0,
  responseBytes: 0,
  timings: { dnsMs: 0, connectMs: 0, tlsMs: 0, ttfbMs: 0, totalMs: 0 },
  request: { size: 0, truncated: false },
  response: { size: 0, truncated: false },
};

class RecordingEventSource {
  static instances: RecordingEventSource[] = [];
  onopen: ((ev: Event) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  closed = false;
  readonly listeners = new Map<string, Set<(ev: MessageEvent<string>) => void>>();

  constructor(public readonly url: string) {
    RecordingEventSource.instances.push(this);
  }

  addEventListener(type: string, fn: (ev: MessageEvent<string>) => void): void {
    const set = this.listeners.get(type) ?? new Set();
    set.add(fn);
    this.listeners.set(type, set);
  }

  dispatch(type: string, data = ""): void {
    for (const fn of this.listeners.get(type) ?? []) {
      fn(new MessageEvent(type, { data }));
    }
  }

  removeEventListener(): void {}

  close(): void {
    this.closed = true;
  }
}

function mockAPI() {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/v1/session")) {
      return json(200, sessionView());
    }
    if (url.includes("/v1/flows/01JH2LIST") && !url.includes("/request") && !url.includes("/response")) {
      return json(200, httpFlow);
    }
    if (url.includes("/v1/flows/01JCONN") && !url.includes("/request") && !url.includes("/response")) {
      return json(200, connectFlow);
    }
    if (url.includes("/v1/flows")) {
      return json(200, {
        revision: "r1",
        storeGeneration: 4,
        nextCursor: null,
        items: [httpFlow, connectFlow],
      });
    }
    return json(404, {
      status: 404,
      title: "not found",
      detail: "not found",
      code: "not_found",
      type: "urn:labmitm:error:not-found",
    });
  });
}

describe("FlowsWorkspace", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    RecordingEventSource.instances = [];
  });

  it("keeps the live list mounted and drives the inspector from selection", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("EventSource", RecordingEventSource);
    vi.stubGlobal("fetch", mockAPI());

    renderApp(<AppRoutes />, { route: "/" });

    expect(await screen.findByText("app.lab.test")).toBeInTheDocument();
    expect(screen.getByText("GET")).toHaveClass("method-http");
    expect(screen.getByText("4ms")).toBeInTheDocument();
    expect(screen.getByText("200")).toHaveClass("status-ok");
    expect(screen.getByText("CONN")).toHaveClass("method-tunnel");
    expect(screen.getByText("-")).toBeInTheDocument();
    expect(screen.getByText("tunnel")).toHaveClass("status-tunnel");
    expect(screen.getByPlaceholderText("Host, method, or status")).toBeInTheDocument();
    expect(screen.getByText(/CONNECT to LDAPS\/TacLab TLS is tunnel-not-decrypt/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /fuzzer|repeater|exploit|relay/i })).toBeNull();
    expect(RecordingEventSource.instances).toHaveLength(1);

    await user.click(screen.getByRole("link", { name: /GET/i }));
    expect(await screen.findByRole("heading", { name: /GET https:\/\/app.lab.test\/login/ })).toBeInTheDocument();
    expect(screen.getByText("h2")).toHaveClass("badge");
    expect(screen.getByText("stream 7")).toHaveClass("badge");
    expect(screen.getByText("SOCKS dest")).toBeInTheDocument();
    expect(screen.getByText("app.lab.test:443")).toBeInTheDocument();
    expect(screen.getByText("Original dest")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.10:443")).toBeInTheDocument();
    expect(screen.getByText("intercepted")).toBeInTheDocument();
    expect(RecordingEventSource.instances).toHaveLength(1);
    expect(RecordingEventSource.instances[0]?.closed).toBe(false);

    await user.click(screen.getByRole("link", { name: /CONN/i }));
    expect(await screen.findByText("Tunnel-not-decrypt")).toBeInTheDocument();
    expect(screen.getByText(/why not decrypted: port not in tls.ports:\[443\]/)).toBeInTheDocument();
    expect(screen.queryByText("No headers.")).toBeNull();
    expect(RecordingEventSource.instances).toHaveLength(1);
  });

  it("filters the list by CONN and tunnel without reconnecting EventSource", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("EventSource", RecordingEventSource);
    vi.stubGlobal("fetch", mockAPI());
    renderApp(<AppRoutes />, { route: "/" });
    expect(await screen.findByText("app.lab.test")).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText("Host, method, or status"), "tunnel");
    expect(screen.getByText("CONN")).toBeInTheDocument();
    expect(screen.queryByText("app.lab.test")).toBeNull();
    expect(RecordingEventSource.instances).toHaveLength(1);
  });

  it("clears selection when Clear succeeds without reconnecting EventSource", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    let wiped = false;
    vi.stubGlobal("EventSource", RecordingEventSource);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url === "/v1/flows" && init?.method === "DELETE") {
          wiped = true;
          return json(200, { deleted: 2 });
        }
        if (url.includes("/v1/flows/01JH2LIST") && !url.includes("/request") && !url.includes("/response")) {
          return json(200, httpFlow);
        }
        if (url.includes("/v1/flows")) {
          return json(200, {
            revision: "r1",
            storeGeneration: wiped ? 5 : 4,
            nextCursor: null,
            items: wiped ? [] : [httpFlow, connectFlow],
          });
        }
        return json(404, {
          status: 404,
          title: "not found",
          detail: "not found",
          code: "not_found",
          type: "urn:labmitm:error:not-found",
        });
      }),
    );
    renderApp(<AppRoutes />, { route: "/flows/01JH2LIST" });
    expect(await screen.findByRole("heading", { name: /GET https:\/\/app.lab.test\/login/ })).toBeInTheDocument();
    expect(RecordingEventSource.instances).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: /Clear flows/i }));
    expect(await screen.findByText("Select a captured flow.")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /GET https:\/\/app.lab.test\/login/ })).toBeNull();
    expect(RecordingEventSource.instances).toHaveLength(1);
  });

  it("drops a deleted selection from SSE without reconnecting EventSource", async () => {
    let gone = false;
    vi.stubGlobal("EventSource", RecordingEventSource);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.includes("/v1/flows/01JH2LIST") && !url.includes("/request") && !url.includes("/response")) {
          return json(200, httpFlow);
        }
        if (url.includes("/v1/flows")) {
          return json(200, {
            revision: "r1",
            storeGeneration: gone ? 5 : 4,
            nextCursor: null,
            items: gone ? [connectFlow] : [httpFlow, connectFlow],
          });
        }
        return json(404, {
          status: 404,
          title: "not found",
          detail: "not found",
          code: "not_found",
          type: "urn:labmitm:error:not-found",
        });
      }),
    );
    renderApp(<AppRoutes />, { route: "/flows/01JH2LIST" });
    expect(await screen.findByRole("heading", { name: /GET https:\/\/app.lab.test\/login/ })).toBeInTheDocument();
    expect(RecordingEventSource.instances).toHaveLength(1);
    gone = true;
    RecordingEventSource.instances[0]?.dispatch("flow.deleted");
    expect(await screen.findByText("Select a captured flow.")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /GET https:\/\/app.lab.test\/login/ })).toBeNull();
    expect(RecordingEventSource.instances).toHaveLength(1);
  });
});
