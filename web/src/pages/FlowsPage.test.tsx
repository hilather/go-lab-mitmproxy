import { act, fireEvent, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../App";
import { json, renderAppReady, resetClientState, sessionView } from "../test/render";
import { portsOnlyState } from "../test/state";

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
    if (url.endsWith("/v1/state")) {
      return json(200, portsOnlyState("sha256:abc", [8443]));
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

function flowLink(method: string, id: string) {
  const link = screen.getByText(method).closest("a");
  expect(link).not.toBeNull();
  expect(link).toHaveAttribute("href", `/flows/${id}`);
  expect(link).toHaveAccessibleName(new RegExp(method));
  expect(link).toBeVisible();
  expect(link!.closest('[aria-hidden="true"]')).toBeNull();
  return link!;
}

describe("FlowsWorkspace", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    RecordingEventSource.instances = [];
  });

  describe("live list selection", () => {
    let getLink: HTMLElement;
    let connLink: HTMLElement;
    beforeEach(async () => {
      vi.stubGlobal("EventSource", RecordingEventSource);
      vi.stubGlobal("fetch", mockAPI());
      await renderAppReady(<AppRoutes />, { route: "/" });
      getLink = flowLink("GET", "01JH2LIST");
      connLink = flowLink("CONN", "01JCONN");
    });

    it("keeps the live list mounted and drives the inspector from selection", async () => {

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

      await act(async () => { fireEvent.click(getLink); });
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

      await act(async () => { fireEvent.click(connLink); });
      expect(await screen.findByText("Tunnel-not-decrypt")).toBeInTheDocument();
      expect(screen.getByText(/why not decrypted: port not in tls.ports:\[443\]/)).toBeInTheDocument();
      expect(screen.queryByText("No headers.")).toBeNull();
      expect(RecordingEventSource.instances).toHaveLength(1);
    });
  });

  it("filters the list by CONN and tunnel without reconnecting EventSource", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("EventSource", RecordingEventSource);
    vi.stubGlobal("fetch", mockAPI());
    await renderAppReady(<AppRoutes />, { route: "/" });
    expect(await screen.findByText("app.lab.test")).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText("Host, method, or status"), "tunnel");
    expect(screen.getByText("CONN")).toBeInTheDocument();
    expect(screen.queryByText("app.lab.test")).toBeNull();
    expect(RecordingEventSource.instances).toHaveLength(1);
  });

  it("clears selection when Clear succeeds without reconnecting EventSource", async () => {
    const user = userEvent.setup();
    const nativeConfirm = vi.spyOn(window, "confirm");
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
    await renderAppReady(<AppRoutes />, { route: "/flows/01JH2LIST" });
    expect(await screen.findByRole("heading", { name: /GET https:\/\/app.lab.test\/login/ })).toBeInTheDocument();
    expect(RecordingEventSource.instances).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: /Clear flows/i }));
    const dialog = screen.getByRole("alertdialog", { name: "Clear every captured flow?" });
    expect(dialog).toHaveTextContent("Deletes every flow in the store: 2 as of the last refresh, plus anything captured since.");
    expect(dialog).not.toHaveTextContent("may hold more");
    expect(dialog).toHaveTextContent("Current store generation 4.");
    expect(within(dialog).getByLabelText("Clear expected store generation (optional)")).toHaveValue(null);
    const generationInput = within(dialog).getByRole("spinbutton", { name: "Clear expected store generation (optional)" });
    const generationLabel = within(dialog).getByText("Clear expected store generation (optional)");
    expect(generationLabel.tagName).toBe("LABEL");
    expect(generationLabel).toHaveAttribute("for", generationInput.id);
    await user.click(within(dialog).getByRole("button", { name: "Clear flows" }));
    expect(nativeConfirm).not.toHaveBeenCalled();
    expect(await screen.findByText("Select a captured flow.")).toBeInTheDocument();
    expect(await screen.findByText("Flows cleared")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /GET https:\/\/app.lab.test\/login/ })).toBeNull();
    expect(RecordingEventSource.instances).toHaveLength(1);
  });

  it("says Clear deletes more than the filtered rows when server filters are applied", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("EventSource", RecordingEventSource);
    const fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/v1/session")) return json(200, sessionView());
      if (url.includes("/v1/flows")) {
        const filtered = url.includes("host=");
        return json(200, { revision: "r1", storeGeneration: 4, nextCursor: null, items: filtered ? [httpFlow] : [httpFlow, connectFlow] });
      }
      return json(404, { status: 404, title: "not found", detail: "not found", code: "not_found", type: "urn:labmitm:error:not-found" });
    });
    vi.stubGlobal("fetch", fetch);
    await renderAppReady(<AppRoutes />, { route: "/" });
    await user.click(await screen.findByRole("button", { name: /^Filters & wait/ }));
    const popover = screen.getByRole("dialog", { name: "Server filters and wait" });
    await user.type(within(popover).getByRole("textbox", { name: /^Host/ }), "app.lab.test");
    await user.click(within(popover).getByRole("button", { name: "Apply filters" }));
    await vi.waitFor(() => expect(fetch.mock.calls.some(([u]) => String(u).includes("host=app.lab.test"))).toBe(true));
    await user.click(screen.getByRole("button", { name: /Clear flows/i }));
    const dialog = screen.getByRole("alertdialog", { name: "Clear every captured flow?" });
    expect(dialog).toHaveTextContent("Deletes every flow in the store, not only the 1 that matches the current server filters.");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
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
    await renderAppReady(<AppRoutes />, { route: "/flows/01JH2LIST" });
    expect(await screen.findByRole("heading", { name: /GET https:\/\/app.lab.test\/login/ })).toBeInTheDocument();
    expect(RecordingEventSource.instances).toHaveLength(1);
    gone = true;
    await act(async () => { RecordingEventSource.instances[0]?.dispatch("flow.deleted"); });
    expect(await screen.findByText("Select a captured flow.")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /GET https:\/\/app.lab.test\/login/ })).toBeNull();
    expect(RecordingEventSource.instances).toHaveLength(1);
  });
});

it("refreshes selected pause actions on SSE without losing replay results", async () => {
  vi.stubGlobal("EventSource", RecordingEventSource);
  let paused = false;
  let generation = 4;
  const current = () => ({ ...httpFlow, state: paused ? "paused" : "completed" });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url === "/v1/session") return json(200, sessionView());
    if (url === "/v1/state") return json(200, portsOnlyState("sha256:abc", [8443]));
    if (url.endsWith(":replay")) return json(200, { ...httpFlow, id: "replayed" });
    if (url.startsWith("/v1/flows/")) return json(200, current());
    return json(200, { revision: "rev", storeGeneration: generation, items: [current()], nextCursor: null });
  }));
  const user = userEvent.setup();
  await renderAppReady(<AppRoutes />, { route: "/flows/01JH2LIST" });
  expect(screen.queryByRole("button", { name: "Resume flow" })).not.toBeInTheDocument();
  paused = true;
  generation++;
  await act(async () => RecordingEventSource.instances[0]?.dispatch("flow.paused"));
  expect(await screen.findByRole("button", { name: "Resume flow" })).toBeEnabled();
  await user.click(screen.getByRole("button", { name: "Replay flow" }));
  await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Replay flow" }));
  expect(await screen.findByRole("link", { name: "Inspect replay replayed" })).toBeVisible();
  generation++;
  await act(async () => RecordingEventSource.instances[0]?.dispatch("flow.inserted"));
  expect(await screen.findByRole("link", { name: "Inspect replay replayed" })).toBeVisible();
  paused = false;
  generation++;
  await act(async () => RecordingEventSource.instances[0]?.dispatch("flow.resumed"));
  expect(screen.queryByRole("button", { name: "Resume flow" })).not.toBeInTheDocument();
  expect(RecordingEventSource.instances).toHaveLength(1);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  RecordingEventSource.instances = [];
  resetClientState();
});

describe("flow list errors", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
    RecordingEventSource.instances = [];
  });
  it("shows list filter field violations instead of only the detail", async () => {
    vi.stubGlobal("EventSource", RecordingEventSource);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) return json(200, sessionView());
        if (url.endsWith("/v1/state")) return json(200, portsOnlyState("sha256:abc", [8443]));
        if (url.includes("/v1/flows"))
          return json(400, {
            status: 400,
            title: "Validation failed",
            detail: "invalid status",
            code: "validation_failed",
            fieldViolations: [{ path: "status", code: "invalid_value", message: "status must be an integer" }],
          });
        return json(404, { code: "not_found", detail: "not found" });
      }),
    );
    await renderAppReady(<AppRoutes />, { route: "/" });
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "invalid status (status: status must be an integer [invalid_value])",
    );
  });
});

describe("flow status chips", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    RecordingEventSource.instances = [];
  });

  const mk = (id: string, host: string, patch: Record<string, unknown>) => ({
    ...httpFlow,
    id,
    host,
    url: `https://${host}/`,
    ...patch,
  });
  const items = [
    mk("01OK", "ok200.lab", { status: 200 }),
    mk("01REDIR", "redir302.lab", { status: 302 }),
    mk("01NF", "nf404.lab", { status: 404 }),
    mk("01BAD", "bad502.lab", { status: 502 }),
    mk("01DROP", "drop0.lab", { status: 0, state: "dropped" }),
    mk("01PAUSE", "pause.lab", { status: 0, state: "paused", pausedPhase: "request" }),
    connectFlow,
  ];

  it("filters loaded rows by status chip with counts, sends no request, and clears from the no-match state", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("EventSource", RecordingEventSource);
    const base = mockAPI();
    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/v1/flows") && !url.includes("/v1/flows/"))
        return json(200, { revision: "r1", storeGeneration: 4, nextCursor: null, items });
      void init;
      return base(input);
    });
    vi.stubGlobal("fetch", fetch);
    await renderAppReady(<AppRoutes />, { route: "/" });
    expect(await screen.findByText("ok200.lab")).toBeInTheDocument();
    const group = screen.getByRole("group", { name: "Status filter" });
    const chip = (name: string) => within(group).getByRole("button", { name: new RegExp(`^${name}`) });
    expect(chip("All")).toHaveTextContent("7");
    expect(chip("All")).toHaveAttribute("aria-pressed", "true");
    expect(chip("Paused")).toHaveTextContent("1");
    expect(chip("2xx")).toHaveTextContent("1");
    expect(chip("4xx")).toHaveTextContent("1");
    expect(chip("5xx")).toHaveTextContent("2");
    const listCalls = () => fetch.mock.calls.filter(([u]) => String(u).includes("/v1/flows") && !String(u).includes("/v1/flows/")).length;
    const before = listCalls();
    const list = screen.getByRole("region", { name: "Captured flows" });

    await user.click(chip("2xx"));
    expect(chip("2xx")).toHaveAttribute("aria-pressed", "true");
    expect(within(list).getByText("ok200.lab")).toBeInTheDocument();
    expect(within(list).queryByText("redir302.lab")).toBeNull();
    expect(within(list).queryByText("directory")).toBeNull();
    expect(within(list).getByText(/^1 of 7$/)).toBeInTheDocument();

    await user.click(chip("5xx"));
    expect(within(list).getByText("bad502.lab")).toBeInTheDocument();
    expect(within(list).getByText("drop0.lab")).toBeInTheDocument();
    expect(within(list).queryByText("nf404.lab")).toBeNull();

    await user.click(chip("Paused"));
    expect(within(list).getByText("pause.lab")).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText("Host, method, or status"), "nomatch");
    expect(within(list).getByText("No flows match")).toBeInTheDocument();
    await user.click(within(list).getByRole("button", { name: "Clear search and status" }));
    expect(chip("All")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByPlaceholderText("Host, method, or status")).toHaveValue("");
    expect(within(list).getByText("redir302.lab")).toBeInTheDocument();
    expect(listCalls()).toBe(before);
  });
});
