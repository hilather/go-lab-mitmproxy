import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, renderApp, resetClientState, sessionView } from "../test/render";
import { StatusPage } from "./StatusPage";

describe("StatusPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("shows ca.spkiSha256 and a cert-only CA download", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/status")) {
          return json(200, {
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
    renderApp(<StatusPage />, { route: "/status" });
    expect(await screen.findByText("deadbeef")).toBeInTheDocument();
    expect(screen.getByText("generate")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /Download lab CA certificate/i });
    expect(link).toHaveAttribute("href", "/v1/ca");
    expect(screen.getByText(/private key is never exported/i)).toBeInTheDocument();
    expect(screen.getByText(/Lab-only intercepting proxy/i)).toBeInTheDocument();
  });
});
