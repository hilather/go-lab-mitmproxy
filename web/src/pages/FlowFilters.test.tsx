import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import {
  json,
  renderAppReady,
  resetClientState,
  sessionView,
} from "../test/render";
import { FlowFilters } from "./FlowFilters";
afterEach(() => {
  resetClientState();
  vi.unstubAllGlobals();
});
it("applies every server list filter and sends only supported wait inputs", async () => {
  const fetch = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) =>
    String(input) === "/v1/session"
      ? json(200, sessionView())
      : json(408, { code: "timeout", detail: "Wait timed out" }),
  );
  vi.stubGlobal("fetch", fetch);
  const filtered = vi.fn();
  const user = userEvent.setup();
  await renderAppReady(<FlowFilters onFilter={filtered} />);
  await user.click(screen.getByText("Server filters and wait"));
  const values = {
    host: "lab",
    method: "POST",
    status: "201",
    pathPrefix: "/test",
    protocol: "h2",
    via: "socks5",
    scheme: "https",
    ruleId: "pause",
  };
  for (const [key, value] of Object.entries(values))
    await user.type(screen.getByLabelText(key), value);
  await user.selectOptions(
    screen.getByLabelText("Intercepted filter"),
    "false",
  );
  await user.click(
    screen.getByRole("button", { name: "Apply server filters" }),
  );
  expect(filtered).toHaveBeenCalledWith({ ...values, intercepted: "false" });
  await user.type(
    screen.getByLabelText("Wait after (RFC3339)"),
    "2026-10-03T00:00:00Z",
  );
  await user.clear(screen.getByLabelText("Wait timeout (Go duration)"));
  await user.type(screen.getByLabelText("Wait timeout (Go duration)"), "5s");
  await user.click(screen.getByRole("button", { name: "Wait for flow" }));
  expect(await screen.findByRole("status")).toHaveTextContent("Wait timed out");
  expect(String(fetch.mock.calls[1]?.[0])).toBe("/v1/flows:wait");
  expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
    filter: {
      host: "lab",
      method: "POST",
      status: 201,
      pathPrefix: "/test",
      protocol: "h2",
      via: "socks5",
      intercepted: false,
      after: "2026-10-03T00:00:00Z",
    },
    timeout: "5s",
  });
});
it("cancels a pending wait with AbortSignal", async () => {
  let signal: AbortSignal | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/v1/session") return json(200, sessionView());
      signal = init?.signal as AbortSignal;
      return new Promise<Response>((_, reject) =>
        signal?.addEventListener("abort", () =>
          reject(new DOMException("Aborted", "AbortError")),
        ),
      );
    }),
  );
  const user = userEvent.setup();
  await renderAppReady(<FlowFilters onFilter={vi.fn()} />);
  await user.click(screen.getByText("Server filters and wait"));
  await user.click(screen.getByRole("button", { name: "Wait for flow" }));
  await user.click(screen.getByRole("button", { name: "Cancel wait" }));
  await waitFor(() => expect(signal?.aborted).toBe(true));
  expect(screen.getByRole("status")).toHaveTextContent("Wait cancelled");
});
it("rejects invalid wait status instead of broadening the filter", async () => {
  const fetch = vi.fn(async () => json(200, sessionView()));
  vi.stubGlobal("fetch", fetch);
  const user = userEvent.setup();
  await renderAppReady(<FlowFilters onFilter={vi.fn()} />);
  await user.click(screen.getByText("Server filters and wait"));
  await user.type(screen.getByLabelText("status"), "abc");
  await user.click(screen.getByRole("button", { name: "Wait for flow" }));
  expect(screen.getByRole("status")).toHaveTextContent(
    "Status must be a non-negative integer",
  );
  expect(fetch).toHaveBeenCalledTimes(1);
});
