import { fireEvent, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  json,
  renderAppReady,
  resetClientState,
  sessionView,
} from "../test/render";
import { DiagnosticsPage } from "./DiagnosticsPage";
import { diagnosticReads } from "../api/diagnostics";
afterEach(() => {
  resetClientState();
  vi.unstubAllGlobals();
});
describe("DiagnosticsPage", () => {
  it("reads every diagnostic using cookie credentials, escapes results, and refreshes", async () => {
    const fetch = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path === "/v1/session") return json(200, sessionView());
      if (path === "/v1/metrics")
        return new Response("# <script>metrics</script>\n# EOF\n");
      if (path === "/v1/health/ready")
        return json(503, { status: "not ready" });
      return json(200, {
        diagnostic: path,
        value: "<img src=x onerror=alert(1)>",
      });
    });
    vi.stubGlobal("fetch", fetch);
    await renderAppReady(<DiagnosticsPage />);
    for (const read of diagnosticReads)
      expect(fetch).toHaveBeenCalledWith(
        read.path,
        expect.objectContaining({ credentials: "same-origin" }),
      );
    expect(screen.getByText(/"httpStatus": 503/)).toBeInTheDocument();
    expect(document.querySelector("main img, main script")).toBeNull();
    expect(
      screen.getByRole("link", { name: "Download configuration schema" }),
    ).toHaveAttribute("href", "/v1/schema/config");
    fireEvent.click(screen.getByRole("button", { name: "Refresh Version" }));
    await within(screen.getByRole("region", { name: "Version" })).findByText(
      /"diagnostic"/,
    );
    expect(
      fetch.mock.calls.filter(([path]) => path === "/v1/version"),
    ).toHaveLength(2);
  });
  it("shows metric errors with bootstrap guidance", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input) === "/v1/session"
          ? json(200, sessionView())
          : String(input) === "/v1/metrics"
            ? json(404, { detail: "metrics public path is disabled" })
            : json(200, {}),
      ),
    );
    await renderAppReady(<DiagnosticsPage />);
    expect(screen.getByRole("alert")).toHaveTextContent(
      "metrics public path is disabled",
    );
    expect(
      screen.getByText(/observability.metrics.publicPath/),
    ).toBeInTheDocument();
  });
  it("does not fetch protected reads without read scope", async () => {
    const fetch = vi.fn(async () =>
      json(200, sessionView(["mitm.audit.read"])),
    );
    vi.stubGlobal("fetch", fetch);
    await renderAppReady(<DiagnosticsPage />);
    expect(screen.getByRole("alert")).toHaveTextContent("mitm.read");
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

it("shows diagnostic field violations instead of only the detail", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) =>
      String(input) === "/v1/session"
        ? json(200, sessionView())
        : String(input) === "/v1/version"
          ? json(400, {
            status: 400,
            title: "Validation failed",
            detail: "unknown fields",
            code: "validation_failed",
            fieldViolations: [
              { path: "reason", code: "unknown_field", message: 'unknown field "reason"' },
            ],
            remediation: "Remove the field.",
          })
          : json(200, {}),
    ),
  );
  await renderAppReady(<DiagnosticsPage />);
  const region = screen.getByRole("region", { name: "Version" });
  expect(await within(region).findByRole("alert")).toHaveTextContent('reason: unknown field "reason" [unknown_field]');
});
