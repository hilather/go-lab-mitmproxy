import { act, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "./App";
import { json, renderAppReady, resetClientState, sessionView } from "./test/render";
import { portsOnlyState, sampleState, sampleStatus } from "./test/state";

// Match the named native element directly, then retain accessibility and
// visibility checks without computing every sibling's accessible name.
function namedElement(name: string | RegExp, selector: string) {
  const element = screen.getByText(name, { selector });
  expect(element).not.toHaveAttribute("role");
  expect(element.closest('[aria-hidden="true"]')).toBeNull();
  expect(element).toHaveAccessibleName(name);
  expect(element).toBeVisible();
  return element;
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

    await renderAppReady(<AppRoutes />, { route: "/" });
    expect(namedElement(/Skip to main content/i, "a")).toHaveAttribute("href", "#app-main");
    expect(namedElement(/LabMITM/i, "a")).toBeInTheDocument();
    expect(screen.getByText("live")).toBeInTheDocument();
    expect(await screen.findByText(":8443 intercept")).toBeInTheDocument();
    expect(screen.queryByText(":443 intercept only")).toBeNull();
    expect(namedElement(/Sign out/i, "button")).toBeInTheDocument();
    expect(namedElement("Flows", "a")).toHaveClass("nav-active");
    expect(screen.queryByRole("button", { name: /fuzzer|repeater|exploit|relay/i })).toBeNull();

    await act(async () => { await user.click(flowLink("GET", "01J")); });
    expect(namedElement(/GET http:\/\/labdns.lab\/v1\/status/, "h1,h2")).toBeInTheDocument();
    expect(namedElement("Flows", "a")).toHaveClass("nav-active");
  });

  it.each(["/status", "/audit", "/reset"] as const)("restyles signed-in %s without tunnel-not-decrypt chips", async (route) => {
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

    const { unmount } = await renderAppReady(<AppRoutes />, { route });
    expect(namedElement(/Skip to main content/i, "a")).toHaveAttribute("href", "#app-main");
    expect(namedElement(/LabMITM/i, "a")).toBeInTheDocument();
    expect(await screen.findByText(":8443 intercept")).toBeInTheDocument();
    expect(screen.queryByText(":443 intercept only")).toBeNull();
    expect(namedElement(/Sign out/i, "button")).toBeInTheDocument();
    expect(namedElement("Flows", "a")).toBeInTheDocument();
    expect(namedElement("Status", "a")).toBeInTheDocument();
    expect(namedElement("Audit", "a")).toBeInTheDocument();
    expect(namedElement("Reset", "a")).toBeInTheDocument();
    const active =
      route === "/status" ? "Status" : route === "/audit" ? "Audit" : "Reset";
    expect(namedElement(active, "a")).toHaveClass("nav-active");
    expect(namedElement(active, "h1,h2")).toBeInTheDocument();
    if (route === "/status") {
      expect(namedElement("Lab CA", "h1,h2")).toBeInTheDocument();
      expect(screen.getByText(/Ready:/)).toBeInTheDocument();
      expect(await screen.findByLabelText("Users (file refs)")).toBeInTheDocument();
      expect(namedElement(/Apply admission/i, "button")).toBeInTheDocument();
      expect(namedElement(/Apply compat/i, "button")).toBeInTheDocument();
    } else if (route === "/audit") {
      expect(await screen.findByText("No audit events.")).toBeInTheDocument();
    } else {
      expect(namedElement(/Reset LabMITM/i, "button")).toBeInTheDocument();
    }
    expect(document.querySelector(".panel")).not.toBeNull();
    expect(screen.queryByText("tunnel-not-decrypt")).toBeNull();
    expect(screen.queryByText("intercepted")).toBeNull();
    expect(screen.queryByRole("button", { name: /fuzzer|repeater|exploit|relay/i })).toBeNull();
    unmount();
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
    await renderAppReady(<AppRoutes />, { route: "/login" });
    expect(namedElement(/Sign in to LabMITM/i, "h1,h2")).toBeInTheDocument();
    expect(namedElement(/LabMITM/i, "a")).toBeInTheDocument();
    expect(screen.getByLabelText(/API bearer token/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Sign out/i })).toBeNull();
    expect(screen.queryByText(":443 intercept only")).toBeNull();
    expect(screen.queryByText("tunnel-not-decrypt")).toBeNull();
    expect(document.querySelector("form.panel")).not.toBeNull();
    const fetchMock = vi.mocked(fetch);
    expect(fetchMock.mock.calls.every((c) => !String(c[0]).endsWith("/v1/state"))).toBe(true);
  });
});
