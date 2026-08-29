import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "./App";
import { json, renderApp, resetClientState, sessionView } from "./test/render";

describe("operator chrome", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("shows skip-link, LabMITM, live and :443 chips, and keeps Flows active on a flow", async () => {
    const user = userEvent.setup();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.includes("/v1/flows/01J") && !url.includes("?")) {
          return json(200, {
            id: "01J",
            state: "completed",
            method: "GET",
            url: "http://labdns.lab/v1/status",
            host: "labdns.lab",
            scheme: "http",
            protocol: "http/1.1",
            status: 200,
            intercepted: true,
            truncated: false,
            requestBytes: 0,
            responseBytes: 12,
            timings: { dnsMs: 0, connectMs: 0, tlsMs: 0, ttfbMs: 0, totalMs: 12 },
            request: { headers: [{ name: "Host", value: "labdns.lab" }], size: 0, truncated: false },
            response: { size: 12, truncated: false },
          });
        }
        if (url.includes("/v1/flows")) {
          return json(200, {
            revision: "r1",
            storeGeneration: 1,
            nextCursor: null,
            items: [
              {
                id: "01J",
                state: "completed",
                method: "GET",
                url: "http://labdns.lab/v1/status",
                host: "labdns.lab",
                scheme: "http",
                protocol: "http/1.1",
                status: 200,
                intercepted: true,
                truncated: false,
                requestBytes: 0,
                responseBytes: 12,
                timings: { dnsMs: 0, connectMs: 0, tlsMs: 0, ttfbMs: 0, totalMs: 12 },
                request: { size: 0, truncated: false },
                response: { size: 12, truncated: false },
              },
            ],
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

    renderApp(<AppRoutes />, { route: "/" });
    expect(await screen.findByRole("link", { name: /Skip to main content/i })).toHaveAttribute("href", "#app-main");
    expect(screen.getByRole("link", { name: /LabMITM/i })).toBeInTheDocument();
    expect(screen.getByText("live")).toBeInTheDocument();
    expect(screen.getByText(":443 intercept only")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Sign out/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Flows" })).toHaveClass("nav-active");
    expect(screen.queryByRole("button", { name: /fuzzer|repeater|exploit|relay/i })).toBeNull();

    await user.click(await screen.findByRole("link", { name: /GET/i }));
    expect(await screen.findByRole("heading", { name: /GET http:\/\/labdns.lab\/v1\/status/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Flows" })).toHaveClass("nav-active");
  });
});
