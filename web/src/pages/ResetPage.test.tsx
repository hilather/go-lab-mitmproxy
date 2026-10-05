import { fireEvent, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, renderAppReady, resetClientState, sessionView } from "../test/render";
import { ResetPage } from "./ResetPage";

describe("ResetPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("keeps reset disabled until RESET is typed and confirmed", async () => {
    const user = userEvent.setup();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input).endsWith("/v1/session")) {
          return json(200, sessionView());
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
    await renderAppReady(<ResetPage />, { route: "/reset" });
    const submit = screen.getByRole("button", { name: /Reset LabMITM/i });
    expect(submit).toBeDisabled();
    const phrase = screen.getByLabelText(/Confirmation phrase/i);
    fireEvent.change(phrase, { target: { value: "RESE" } });
    expect(submit).toBeDisabled();
    fireEvent.change(phrase, { target: { value: "RESET" } });
    expect(submit).toBeDisabled();
    await user.click(screen.getByLabelText(/Wipe the flow store/i));
    expect(submit).toBeEnabled();
    fireEvent.change(phrase, { target: { value: "RESE" } });
    expect(submit).toBeDisabled();
  });

  it("shows field violations and remediation when reset is rejected", async () => {
    const user = userEvent.setup();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/state:reset")) {
          return json(400, {
            status: 400,
            title: "validation failed",
            detail: "request validation failed",
            code: "validation_failed",
            type: "urn:labmitm:error:validation-failed",
            fieldViolations: [{ path: "reason", message: "unknown field \"reason\"", code: "unknown_field" }],
            remediation: "Free the listener port and retry.",
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
    await renderAppReady(<ResetPage />, { route: "/reset" });
    fireEvent.change(screen.getByLabelText(/Confirmation phrase/i), { target: { value: "RESET" } });
    await user.click(screen.getByLabelText(/Wipe the flow store/i));
    await user.click(screen.getByRole("button", { name: /Reset LabMITM/i }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent('reason: unknown field "reason" [unknown_field]');
    expect(alert).toHaveTextContent("Remediation: Free the listener port and retry.");
  });

  it("shows the impact line from GET /v1/status and re-reads it on tick and after reset", async () => {
    const user = userEvent.setup();
    let flows = 12;
    const fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/v1/session")) return json(200, sessionView());
      if (url.endsWith("/v1/status"))
        return json(200, { store: { flowCount: flows, storeBytes: 0, storeGeneration: flows === 0 ? 4 : 3, epoch: 1 } });
      if (url.endsWith("/v1/state:reset")) {
        flows = 0;
        return json(200, {});
      }
      return json(404, { status: 404, code: "not_found", detail: "not found" });
    });
    vi.stubGlobal("fetch", fetch);
    await renderAppReady(<ResetPage />, { route: "/reset" });
    expect(await screen.findByTestId("reset-impact")).toHaveTextContent(/Snapshot at .*: 12 flows · store generation 3\./);
    const statusCalls = () => fetch.mock.calls.filter(([p]) => String(p).endsWith("/v1/status")).length;
    expect(statusCalls()).toBe(1);
    fireEvent.change(screen.getByLabelText(/Confirmation phrase/i), { target: { value: "RESET" } });
    await user.click(screen.getByLabelText(/Wipe the flow store/i));
    expect(statusCalls()).toBe(2);
    const submit = screen.getByRole("button", { name: /Reset LabMITM/i });
    expect(submit).toHaveClass("btn-danger-fill");
    await user.click(submit);
    expect(await screen.findByTestId("reset-impact")).toHaveTextContent(/Snapshot at .*: 0 flows · store generation 4\./);
    expect(statusCalls()).toBe(3);
  });

  it("labels the impact line as a snapshot and re-reads it on Refresh count", async () => {
    const user = userEvent.setup();
    let flows = 5;
    const fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/v1/session")) return json(200, sessionView());
      if (url.endsWith("/v1/status")) return json(200, { store: { flowCount: flows, storeBytes: 0, storeGeneration: 2, epoch: 1 } });
      return json(404, { status: 404, code: "not_found", detail: "not found" });
    });
    vi.stubGlobal("fetch", fetch);
    await renderAppReady(<ResetPage />, { route: "/reset" });
    const impact = await screen.findByTestId("reset-impact");
    expect(impact).toHaveTextContent(/Snapshot at .*: 5 flows · store generation 2\./);
    expect(impact).toHaveTextContent("Not live: Reset wipes whatever the store holds when it runs.");
    const statusCalls = () => fetch.mock.calls.filter(([p]) => String(p).endsWith("/v1/status")).length;
    expect(statusCalls()).toBe(1);
    flows = 1;
    await user.click(screen.getByRole("button", { name: "Refresh count" }));
    expect(await screen.findByText(/: 1 flow · store generation 2\./)).toBeInTheDocument();
    expect(statusCalls()).toBe(2);
  });

  it("hides the impact line without an alert when /v1/status fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input).endsWith("/v1/session")
          ? json(200, sessionView())
          : json(404, { status: 404, code: "not_found", detail: "not found" }),
      ),
    );
    await renderAppReady(<ResetPage />, { route: "/reset" });
    await vi.waitFor(() => expect(screen.queryByTestId("reset-impact")).toBeNull());
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
