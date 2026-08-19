import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, renderApp, resetClientState, sessionView } from "../test/render";
import { FlowPage } from "./FlowPage";

const flow = {
  id: "01JTEST",
  startedAt: "2026-08-18T00:00:00Z",
  state: "completed",
  method: "GET",
  url: "https://app.lab.test/login",
  host: "app.lab.test",
  scheme: "https",
  protocol: "http/1.1",
  status: 200,
  intercepted: true,
  truncated: false,
  requestBytes: 0,
  responseBytes: 12,
  timings: { dnsMs: 0, connectMs: 1, tlsMs: 2, ttfbMs: 3, totalMs: 4 },
  request: {
    headers: [{ name: "Host", value: "app.lab.test" }],
    body: "",
    size: 0,
    truncated: false,
  },
  response: {
    headers: [{ name: "Content-Type", value: "text/html" }],
    body: "<html><body><script>alert(1)</script>ok</body></html>",
    size: 12,
    truncated: false,
  },
  tls: {
    sni: "app.lab.test",
    version: "TLS 1.3",
    cipherSuite: "TLS_AES_128_GCM_SHA256",
    alpn: "http/1.1",
    upstreamVerified: true,
    leafDns: ["app.lab.test"],
  },
};

describe("FlowPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("loads a flow and renders HTML as escaped text", async () => {
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/v1/session")) {
        return json(200, sessionView());
      }
      if (url.includes("/v1/flows/01JTEST") && !url.includes("/request") && !url.includes("/response")) {
        return json(200, flow);
      }
      return json(404, {
        status: 404,
        title: "not found",
        detail: "not found",
        code: "not_found",
        type: "urn:labmitm:error:not-found",
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderApp(
      <Routes>
        <Route path="/flows/:id" element={<FlowPage />} />
      </Routes>,
      { route: "/flows/01JTEST" },
    );
    expect(await screen.findByRole("heading", { name: /GET https:\/\/app.lab.test\/login/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /fuzzer|repeater|exploit|relay/i })).toBeNull();

    await user.click(screen.getByRole("tab", { name: /Response/i }));
    expect(await screen.findByText(/<script>alert\(1\)<\/script>/)).toBeInTheDocument();
    expect(document.querySelector("iframe")).toBeNull();
    expect(document.querySelector("[dangerouslySetInnerHTML]")).toBeNull();
    expect(screen.getByRole("link", { name: /Download response body/i })).toHaveAttribute(
      "href",
      "/v1/flows/01JTEST/response",
    );
    await waitFor(() => {
      expect(fetchMock.mock.calls.some((c) => String(c[0]).includes("/v1/flows/01JTEST"))).toBe(true);
    });
  });
});
