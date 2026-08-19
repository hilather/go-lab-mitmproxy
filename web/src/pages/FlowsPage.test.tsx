import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, renderApp, resetClientState, sessionView } from "../test/render";
import { FlowsPage } from "./FlowsPage";

describe("FlowsPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("shows protocol badge, stream id, SOCKS dest, and original dest on the list", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.includes("/v1/flows")) {
          return json(200, {
            revision: "r1",
            storeGeneration: 4,
            nextCursor: null,
            items: [
              {
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

    renderApp(<FlowsPage />, { route: "/" });
    expect(await screen.findByRole("link", { name: /200\s+app\.lab\.test/ })).toBeInTheDocument();
    expect(screen.getByText("h2")).toHaveClass("badge");
    expect(screen.getByText("stream 7")).toHaveClass("badge");
    expect(screen.getByText(/SOCKS dest\s+app.lab.test:443/)).toBeInTheDocument();
    expect(screen.getByText(/original dest\s+192.0.2.10:443/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /fuzzer|repeater|exploit|relay/i })).toBeNull();
  });
});
