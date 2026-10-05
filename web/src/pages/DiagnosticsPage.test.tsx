import { fireEvent, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  json,
  renderAppReady,
  resetClientState,
  sessionView,
} from "../test/render";
import { localTime } from "../ui/time";
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
    const checked = document.querySelector("time[datetime][title]");
    expect(checked).not.toBeNull();
    expect(checked!.getAttribute("title")).toBe(checked!.getAttribute("dateTime"));
    expect(Number.isFinite(Date.parse(checked!.getAttribute("title")!))).toBe(true);
    expect(checked!.textContent).toBe(localTime(checked!.getAttribute("title")!));
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

function diagFetch(overrides: Record<string, () => Response>) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path === "/v1/session") return json(200, sessionView());
    const make = overrides[path];
    return make ? make() : json(200, { status: "ok" });
  });
}

it("shows the designed metrics-disabled state with the restart instruction for 404 not_found", async () => {
  vi.stubGlobal(
    "fetch",
    diagFetch({
      "/v1/metrics": () => json(404, { status: 404, code: "not_found", detail: "not found" }),
    }),
  );
  await renderAppReady(<DiagnosticsPage />);
  const metrics = screen.getByRole("region", { name: metricsTitle() });
  expect(await within(metrics).findByText("Metrics are disabled.")).toBeInTheDocument();
  expect(metrics).toHaveTextContent(
    "Set observability.metrics.publicPath: true in bootstrap YAML and restart labmitm.",
  );
  // The key breaks only after its dots (<wbr>), never mid-token in a narrow tile.
  const key = within(metrics).getByText("observability.metrics.publicPath: true", { selector: "code" });
  expect(key.querySelectorAll("wbr")).toHaveLength(2);
  expect(key.innerHTML).toBe("observability.<wbr>metrics.<wbr>publicPath: true");
  expect(metrics.textContent).not.toMatch(/Reset/);
  expect(within(metrics).queryByRole("alert")).toBeNull();
});

it("keeps a 403 metrics error as an alert, not the disabled state", async () => {
  vi.stubGlobal(
    "fetch",
    diagFetch({
      "/v1/metrics": () => json(403, { status: 403, code: "forbidden", detail: "forbidden metrics" }),
    }),
  );
  await renderAppReady(<DiagnosticsPage />);
  const metrics = screen.getByRole("region", { name: metricsTitle() });
  expect(await within(metrics).findByRole("alert")).toHaveTextContent("forbidden metrics");
  expect(within(metrics).queryByText("Metrics are disabled.")).toBeNull();
});

it("shows Protocols from the version read and a Ver column without extra requests", async () => {
  const fetch = diagFetch({
    "/v1/version": () =>
      json(200, {
        version: "dev",
        commit: "d6794d228db0aaaa",
        buildTime: "2026-10-03T20:01:36Z",
        protocols: { rest: "/v1", mcp: "2026-07-28", configAPI: "labmitm.dev/v1alpha1" },
      }),
    "/v1/capabilities": () =>
      json(200, {
        capabilities: [
          { name: "health.live", mutating: false, idempotent: true, version: "v1", description: "Process liveness." },
          { name: "mitm_change_apply", mutating: true, idempotent: true, version: "v2", description: "Apply operations." },
        ],
      }),
  });
  vi.stubGlobal("fetch", fetch);
  await renderAppReady(<DiagnosticsPage />);
  const protocols = screen.getByRole("region", { name: "Protocols" });
  expect(await within(protocols).findByText("labmitm.dev/v1alpha1")).toBeInTheDocument();
  expect(protocols).toHaveTextContent("2026-07-28");
  expect(fetch.mock.calls.filter(([p]) => p === "/v1/version")).toHaveLength(1);
  const table = await screen.findByRole("table", { name: "Capabilities table" });
  expect(within(table).getByRole("columnheader", { name: "Ver" })).toBeInTheDocument();
  expect(within(table).getByRole("row", { name: /mitm_change_apply mutating yes v2/ })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /^Mutating/ }));
  expect(within(table).queryByText("health.live")).toBeNull();
});

it("Refresh all re-runs every diagnostic read once", async () => {
  const fetch = diagFetch({});
  vi.stubGlobal("fetch", fetch);
  await renderAppReady(<DiagnosticsPage />);
  await screen.findAllByText(/^Raw /);
  fireEvent.click(screen.getByRole("button", { name: "Refresh all" }));
  await vi.waitFor(() => {
    for (const read of diagnosticReads)
      expect(fetch.mock.calls.filter(([p]) => p === read.path)).toHaveLength(2);
  });
});

function metricsTitle(): string {
  return diagnosticReads.find((r) => r.id === "metrics.get")!.title;
}
