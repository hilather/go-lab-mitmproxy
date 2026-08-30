import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "./App";
import { json, renderApp, resetClientState, sessionView } from "./test/render";
import { portsOnlyState, sampleState, sampleStatus } from "./test/state";

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
        if (url.endsWith("/v1/state")) {
          return json(200, portsOnlyState("sha256:abc", [8443]));
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
    expect(await screen.findByText(":8443 intercept")).toBeInTheDocument();
    expect(screen.queryByText(":443 intercept only")).toBeNull();
    expect(screen.getByRole("button", { name: /Sign out/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Flows" })).toHaveClass("nav-active");
    expect(screen.queryByRole("button", { name: /fuzzer|repeater|exploit|relay/i })).toBeNull();

    await user.click(await screen.findByRole("link", { name: /GET/i }));
    expect(await screen.findByRole("heading", { name: /GET http:\/\/labdns.lab\/v1\/status/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Flows" })).toHaveClass("nav-active");
  });

  it("restyles signed-in leftover routes without tunnel-not-decrypt chips", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/status")) {
          return json(200, sampleStatus());
        }
        if (url.endsWith("/v1/state")) {
          return json(200, sampleState("sha256:abc", [8443]));
        }
        if (url.endsWith("/v1/features")) {
          return json(200, {
            runtimeRevision: "sha256:abc",
            generation: 1,
            drifted: false,
            items: [
              {
                id: "rules.enabled",
                yamlPath: "spec.rules.enabled",
                title: "rules.enabled",
                description: "Rules engine master switch",
                enabled: false,
                applyMode: "live",
                verb: "setFeature",
              },
            ],
          });
        }
        if (url.endsWith("/v1/audit")) {
          return json(200, { events: [] });
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

    for (const route of ["/status", "/audit", "/reset"] as const) {
      const { unmount } = renderApp(<AppRoutes />, { route });
      expect(await screen.findByRole("link", { name: /Skip to main content/i })).toHaveAttribute("href", "#app-main");
      expect(screen.getByRole("link", { name: /LabMITM/i })).toBeInTheDocument();
      expect(await screen.findByText(":8443 intercept")).toBeInTheDocument();
      expect(screen.queryByText(":443 intercept only")).toBeNull();
      expect(screen.getByRole("button", { name: /Sign out/i })).toBeInTheDocument();
      expect(screen.getByRole("link", { name: "Flows" })).toBeInTheDocument();
      expect(screen.getByRole("link", { name: "Status" })).toBeInTheDocument();
      expect(screen.getByRole("link", { name: "Audit" })).toBeInTheDocument();
      expect(screen.getByRole("link", { name: "Reset" })).toBeInTheDocument();
      const active =
        route === "/status" ? "Status" : route === "/audit" ? "Audit" : "Reset";
      expect(screen.getByRole("link", { name: active })).toHaveClass("nav-active");
      expect(await screen.findByRole("heading", { name: active })).toBeInTheDocument();
      if (route === "/status") {
        expect(await screen.findByRole("heading", { name: "Lab CA" })).toBeInTheDocument();
        expect(screen.getByText(/Ready:/)).toBeInTheDocument();
        expect(await screen.findByLabelText("Users (file refs)")).toBeInTheDocument();
        expect(screen.getByRole("button", { name: /Apply admission/i })).toBeInTheDocument();
        expect(screen.getByRole("button", { name: /Apply compat/i })).toBeInTheDocument();
      } else if (route === "/audit") {
        expect(await screen.findByText("No audit events.")).toBeInTheDocument();
      } else {
        expect(await screen.findByRole("button", { name: /Reset LabMITM/i })).toBeInTheDocument();
      }
      expect(document.querySelector(".panel")).not.toBeNull();
      expect(screen.queryByText("tunnel-not-decrypt")).toBeNull();
      expect(screen.queryByText("intercepted")).toBeNull();
      expect(screen.queryByRole("button", { name: /fuzzer|repeater|exploit|relay/i })).toBeNull();
      unmount();
    }
  });

  it("restyles the signed-out login page body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input).endsWith("/v1/session")) {
          return json(401, {
            status: 401,
            title: "unauthenticated",
            detail: "authentication required",
            code: "unauthenticated",
            type: "urn:labmitm:error:unauthenticated",
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
    renderApp(<AppRoutes />, { route: "/login" });
    expect(await screen.findByRole("heading", { name: /Sign in to LabMITM/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /LabMITM/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/API bearer token/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Sign out/i })).toBeNull();
    expect(screen.queryByText(":443 intercept only")).toBeNull();
    expect(screen.queryByText("tunnel-not-decrypt")).toBeNull();
    expect(document.querySelector("form.panel")).not.toBeNull();
    const fetchMock = vi.mocked(fetch);
    expect(fetchMock.mock.calls.every((c) => !String(c[0]).endsWith("/v1/state"))).toBe(true);
  });
});
