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
});
