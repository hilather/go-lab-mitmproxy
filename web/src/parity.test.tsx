import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "./App";
import { getMemoryCSRF } from "./api/client";
import {
  json,
  renderAppReady,
  resetClientState,
  sessionView,
} from "./test/render";
import { sampleState, sampleStatus } from "./test/state";

const manifest = JSON.parse(readFileSync(resolve("parity.json"), "utf8")) as {
  capabilities: Record<string, { route: string }>;
  operations: Record<string, { route: string }>;
};
const routes = [
  ...new Set(
    Object.values({ ...manifest.capabilities, ...manifest.operations }).map(
      (row) => row.route,
    ),
  ),
];
const flow = {
  id: "parity-flow",
  state: "completed",
  method: "GET",
  url: "http://lab.test/parity",
  host: "lab.test",
  scheme: "http",
  protocol: "http/1.1",
  status: 200,
  intercepted: false,
  truncated: false,
  requestBytes: 0,
  responseBytes: 0,
  timings: { dnsMs: 0, connectMs: 0, tlsMs: 0, ttfbMs: 0, totalMs: 1 },
  request: { headers: [], size: 0, truncated: false },
  response: { headers: [], size: 0, truncated: false },
};

function stubAPI(signedIn = true) {
  const mock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost");
    if (url.pathname === "/v1/session") {
      if (init?.method === "DELETE") return new Response(null, { status: 204 });
      return signedIn
        ? json(200, sessionView())
        : json(401, { detail: "Sign in" });
    }
    if (url.pathname === "/v1/state") return json(200, sampleState());
    if (url.pathname === "/v1/status") return json(200, sampleStatus());
    if (url.pathname === "/v1/features")
      return json(200, { items: [], runtimeRevision: "sha256:abc" });
    if (url.pathname === "/v1/audit") return json(200, { events: [] });
    if (url.pathname === "/v1/flows")
      return json(200, {
        items: [flow],
        storeGeneration: 1,
        revision: "r",
        nextCursor: null,
      });
    if (url.pathname === `/v1/flows/${flow.id}`)
      return init?.method === "DELETE"
        ? new Response(null, { status: 204 })
        : json(200, flow);
    if (url.pathname.endsWith("/request") || url.pathname.endsWith("/response"))
      return new Response("<script>captured</script>");
    return json(200, {});
  });
  vi.stubGlobal("fetch", mock);
  return mock;
}

afterEach(() => {
  resetClientState();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("frontend parity routes", () => {
  it.each(routes)("renders %s", async (route) => {
    const headings: Record<string, string> = {
      "/login": "Sign in to LabMITM",
      "/status": "Status",
      "/configuration": "Configuration",
      "/diagnostics": "Diagnostics",
      "/audit": "Audit",
      "/reset": "Reset",
      "/flows/:id": "GET http://lab.test/parity",
    };
    // A newly declared route must have an explicit visible page expectation.
    expect(route === "/" || Object.hasOwn(headings, route)).toBe(true);
    stubAPI(route !== "/login");
    await renderAppReady(<AppRoutes />, {
      route: route.replace(":id", flow.id),
    });
    if (route === "/")
      expect(
        screen.getByRole("region", { name: "Captured flows" }),
      ).toBeVisible();
    else
      expect(
        screen.getByRole("heading", { name: headings[route]!, level: 1 }),
      ).toBeVisible();
    if (route !== "/login" && route !== "/flows/:id") {
      expect(document.querySelector(`nav a[href="${route}"]`)).toHaveAttribute(
        "aria-current",
        "page",
      );
    }
  });

  it("signs out through the session adapter and clears the CSRF secret", async () => {
    const mock = stubAPI();
    await renderAppReady(<AppRoutes />, { route: "/diagnostics" });
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByRole("heading", { name: "Sign in to LabMITM" });
    expect(mock).toHaveBeenCalledWith(
      "/v1/session",
      expect.objectContaining({ method: "DELETE", credentials: "same-origin" }),
    );
    const call = mock.mock.calls.find(([, init]) => init?.method === "DELETE");
    expect(new Headers(call?.[1]?.headers).get("X-LabMITM-CSRF")).toBe(
      "csrf-test",
    );
    expect(getMemoryCSRF()).toBe("");
  });

  it("downloads both bodies from the inspector and deletes with a generation precondition", async () => {
    const mock = stubAPI();
    vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:parity");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {});
    vi.spyOn(window, "confirm").mockReturnValue(true);
    await renderAppReady(<AppRoutes />, { route: `/flows/${flow.id}` });
    fireEvent.click(
      screen.getByRole("link", { name: "Download request body" }),
    );
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("tab", { name: "Response" }));
    fireEvent.click(
      screen.getByRole("link", { name: "Download response body" }),
    );
    await waitFor(() => expect(click).toHaveBeenCalledTimes(2));
    for (const side of ["request", "response"]) {
      expect(mock).toHaveBeenCalledWith(
        `/v1/flows/${flow.id}/${side}`,
        expect.objectContaining({ credentials: "same-origin" }),
      );
    }
    expect(document.querySelector("main script")).toBeNull();
    fireEvent.change(
      screen.getByLabelText("Delete expected store generation (optional)"),
      { target: { value: "1" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(mock).toHaveBeenCalledWith(
        `/v1/flows/${flow.id}?expectedStoreGeneration=1`,
        expect.objectContaining({ method: "DELETE" }),
      ),
    );
    await screen.findByText("Select a captured flow.");
  });
});
