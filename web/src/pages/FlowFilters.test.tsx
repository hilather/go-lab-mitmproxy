import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import {
  json,
  renderAppReady,
  resetClientState,
  sessionView,
} from "../test/render";
import { LiveSpecProvider } from "../api/liveSpec";
import { sampleState } from "../test/state";
import { FlowFilters, goDurationMs } from "./FlowFilters";
function fieldInput(key: string) {
  return screen.getByLabelText(new RegExp(` ${key}( list only)?$`));
}
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
  // Many fields are typed here; skip per-character timers so a loaded host does not hit the 5s test deadline.
  const user = userEvent.setup({ delay: null });
  await renderAppReady(<FlowFilters onFilter={filtered} />);
  await user.click(screen.getByRole("button", { name: "Filters & wait" }));
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
    await user.type(fieldInput(key), value);
  await user.click(screen.getByRole("radio", { name: "Not intercepted" }));
  await user.click(
    screen.getByRole("button", { name: "Apply filters" }),
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
  await user.click(screen.getByRole("button", { name: "Filters & wait" }));
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
  await user.click(screen.getByRole("button", { name: "Filters & wait" }));
  await user.type(fieldInput("status"), "abc");
  await user.click(screen.getByRole("button", { name: "Wait for flow" }));
  expect(screen.getByRole("status")).toHaveTextContent(
    "Status must be a non-negative integer",
  );
  expect(fetch).toHaveBeenCalledTimes(1);
});

it("shows wait field violations instead of only the detail", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) =>
      String(input) === "/v1/session"
        ? json(200, sessionView())
        : json(400, {
          status: 400,
          title: "Validation failed",
          detail: "unknown fields",
          code: "validation_failed",
          fieldViolations: [
            { path: "reason", code: "unknown_field", message: 'unknown field "reason"' },
          ],
          remediation: "Remove the field.",
        }),
    ),
  );
  const user = userEvent.setup();
  await renderAppReady(<FlowFilters onFilter={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Filters & wait" }));
  await user.click(screen.getByRole("button", { name: "Wait for flow" }));
  await waitFor(() =>
    expect(screen.getByRole("status")).toHaveTextContent('reason: unknown field "reason" [unknown_field]'),
  );
  expect(screen.getByRole("status")).toHaveTextContent("Remediation: Remove the field.");
});

it("keeps a running wait alive when the popover closes", async () => {
  let signal: AbortSignal | undefined;
  let resolveWait: ((r: Response) => void) | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/v1/session") return json(200, sessionView());
      signal = init?.signal as AbortSignal;
      return new Promise<Response>((resolve) => {
        resolveWait = resolve;
      });
    }),
  );
  const user = userEvent.setup();
  await renderAppReady(<FlowFilters onFilter={vi.fn()} />);
  const trigger = screen.getByRole("button", { name: "Filters & wait" });
  await user.click(trigger);
  await user.click(screen.getByRole("button", { name: "Wait for flow" }));
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog", { name: "Server filters and wait" })).toBeNull();
  expect(screen.getByText(/^Waiting · \d+s of 30s$/)).toBeInTheDocument();
  expect(screen.getByRole("progressbar", { name: "Wait progress" })).toBeInTheDocument();
  await user.click(trigger);
  await user.click(document.body);
  expect(screen.queryByRole("dialog", { name: "Server filters and wait" })).toBeNull();
  expect(signal?.aborted).toBe(false);
  resolveWait?.(json(200, { id: "matched-1" }));
  expect(await screen.findByRole("status")).toHaveTextContent("Matched flow matched-1");
  expect(screen.queryByText(/^Waiting ·/)).toBeNull();
});

it("keeps unapplied values across close and reopen, and chip removal re-applies", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(200, sessionView())));
  const filtered = vi.fn();
  const user = userEvent.setup();
  await renderAppReady(<FlowFilters onFilter={filtered} />);
  const trigger = screen.getByRole("button", { name: "Filters & wait" });
  await user.click(trigger);
  await user.type(fieldInput("host"), "shop.lab");
  await user.type(fieldInput("method"), "POST");
  await user.click(screen.getByRole("button", { name: "Apply filters" }));
  expect(filtered).toHaveBeenLastCalledWith({ host: "shop.lab", method: "POST" });
  await user.type(fieldInput("via"), "http");
  await user.click(trigger);
  await user.click(screen.getByRole("button", { name: "Filters & wait · 2" }));
  expect(fieldInput("via")).toHaveValue("http");
  await user.keyboard("{Escape}");
  await user.click(screen.getByRole("button", { name: "Remove filter host: shop.lab" }));
  // Only the applied filters minus host are re-applied; the unapplied via edit stays a draft.
  expect(filtered).toHaveBeenLastCalledWith({ method: "POST" });
  expect(fieldInput("host")).toHaveValue("");
  expect(fieldInput("via")).toHaveValue("http");
  await user.click(screen.getByRole("button", { name: "Clear filters" }));
  expect(filtered).toHaveBeenLastCalledWith({});
});

it("offers live rule IDs as ruleId suggestions", async () => {
  const state = sampleState();
  state.canonical!.spec!.rules = {
    enabled: true,
    items: [
      { id: "pause-checkout", phase: "request", action: { type: "breakpoint" } },
      { id: "drop-login", phase: "request", action: { type: "drop" } },
    ],
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) =>
      String(input) === "/v1/state" ? json(200, state) : json(200, sessionView()),
    ),
  );
  const user = userEvent.setup();
  await renderAppReady(
    <LiveSpecProvider>
      <FlowFilters onFilter={vi.fn()} />
    </LiveSpecProvider>,
  );
  await user.click(screen.getByRole("button", { name: "Filters & wait" }));
  await waitFor(() => expect(fieldInput("ruleId").getAttribute("list")).not.toBeNull());
  const list = document.getElementById(fieldInput("ruleId").getAttribute("list") ?? "");
  const options = Array.from(list?.querySelectorAll("option") ?? []);
  expect(options.map((o) => [o.value, o.label])).toEqual([
    ["pause-checkout", "breakpoint · request"],
    ["drop-login", "drop · request"],
  ]);
});

it("parses Go durations for wait progress", () => {
  expect(goDurationMs("30s")).toBe(30000);
  expect(goDurationMs("1m30s")).toBe(90000);
  expect(goDurationMs("250ms")).toBe(250);
  expect(goDurationMs("soon")).toBeNull();
});

it("shows a wait timeout in the list head when the popover is closed", async () => {
  let resolveWait: ((r: Response) => void) | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      if (String(input) === "/v1/session") return json(200, sessionView());
      return new Promise<Response>((resolve) => {
        resolveWait = resolve;
      });
    }),
  );
  const user = userEvent.setup();
  await renderAppReady(<FlowFilters onFilter={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Filters & wait" }));
  await user.click(screen.getByRole("button", { name: "Wait for flow" }));
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog", { name: "Server filters and wait" })).toBeNull();
  resolveWait?.(json(408, { code: "timeout", detail: "Wait timed out" }));
  expect(await screen.findByRole("status")).toHaveTextContent("Wait timed out");
  expect(screen.getAllByRole("status")).toHaveLength(1);
  expect(document.querySelectorAll(".wait-message")).toHaveLength(1);
  await user.click(screen.getByRole("button", { name: "Dismiss" }));
  expect(screen.queryByRole("status")).toBeNull();
});

it("shows Wait cancelled after cancelling from the list head with the popover closed", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/v1/session") return json(200, sessionView());
      const signal = init?.signal as AbortSignal;
      return new Promise<Response>((_, reject) =>
        signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError"))),
      );
    }),
  );
  const user = userEvent.setup();
  await renderAppReady(<FlowFilters onFilter={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Filters & wait" }));
  await user.click(screen.getByRole("button", { name: "Wait for flow" }));
  await user.keyboard("{Escape}");
  await user.click(screen.getByRole("button", { name: "Cancel wait" }));
  expect(await screen.findByRole("status")).toHaveTextContent("Wait cancelled.");
  expect(screen.getAllByRole("status")).toHaveLength(1);
});

it("moves focus into the popover on open and returns it to the trigger on Escape", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(200, sessionView())));
  const user = userEvent.setup();
  await renderAppReady(<FlowFilters onFilter={vi.fn()} />);
  const trigger = screen.getByRole("button", { name: "Filters & wait" });
  await user.click(trigger);
  const host = fieldInput("host");
  expect(host).toHaveFocus();
  expect(screen.getByRole("dialog", { name: "Server filters and wait" })).toContainElement(host);
  // Typing while open is not interrupted by a re-render.
  await user.keyboard("lab");
  expect(host).toHaveValue("lab");
  expect(host).toHaveFocus();
  await user.keyboard("{Escape}");
  expect(trigger).toHaveFocus();
  // Reopening focuses the first field again.
  await user.click(trigger);
  expect(fieldInput("host")).toHaveFocus();
  // An outside click hides the popover; focus follows the click and is never left inside the hidden popover.
  await user.click(document.body);
  expect(screen.queryByRole("dialog", { name: "Server filters and wait" })).toBeNull();
  expect(document.querySelector(".popover")?.contains(document.activeElement)).toBe(false);
});
