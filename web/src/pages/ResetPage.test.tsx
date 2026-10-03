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
});
