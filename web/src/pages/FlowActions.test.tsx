import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import type { Flow } from "../api/types";
import {
  json,
  renderAppReady,
  resetClientState,
  sessionView,
} from "../test/render";
import { FlowActions } from "./FlowActions";
const flow: Flow = {
  id: "one",
  state: "paused",
  pausedPhase: "response",
  method: "GET",
  url: "http://lab/",
  host: "lab",
  scheme: "http",
  protocol: "http/1.1",
  status: 200,
  intercepted: false,
  truncated: false,
  requestBytes: 0,
  responseBytes: 0,
  request: { size: 0, truncated: false },
  response: { size: 0, truncated: false },
  timings: { dnsMs: 0, connectMs: 0, tlsMs: 0, ttfbMs: 0, totalMs: 0 },
};
afterEach(() => {
  resetClientState();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
function mock(scopes = ["mitm.read", "mitm.write"], error = false) {
  const fetch = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) =>
    String(input) === "/v1/session"
      ? json(200, sessionView(scopes))
      : error
        ? json(409, { code: "conflict", detail: "No longer paused" })
        : String(input).endsWith(":replay")
          ? json(200, { ...flow, id: "replayed", state: "completed" })
          : new Response(null, { status: 204 }),
  );
  vi.stubGlobal("fetch", fetch);
  return fetch;
}
it("preserves omitted edits and sends explicitly empty headers/body", async () => {
  const fetch = mock();
  const user = userEvent.setup();
  const changed = vi.fn();
  await renderAppReady(<FlowActions flow={flow} onChanged={changed} />);
  await user.click(screen.getByRole("button", { name: "Resume flow" }));
  await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
  expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({});
  await user.click(screen.getByLabelText("Replace headers"));
  await user.click(screen.getByLabelText("Replace body"));
  await user.click(screen.getByRole("button", { name: "Resume flow" }));
  await waitFor(() => expect(changed).toHaveBeenCalledTimes(2));
  expect(JSON.parse(String(fetch.mock.calls[2]?.[1]?.body))).toEqual({
    headers: [],
    body: "",
  });
});
it("sends edited header rows/body and displays server errors", async () => {
  const fetch = mock(undefined, true);
  const user = userEvent.setup();
  await renderAppReady(<FlowActions flow={flow} onChanged={vi.fn()} />);
  await user.click(screen.getByLabelText("Replace headers"));
  await user.click(screen.getByRole("button", { name: "Add header" }));
  await user.type(screen.getByLabelText("Header name 1"), "X-Lab");
  await user.type(screen.getByLabelText("Header value 1"), "test");
  await user.click(screen.getByLabelText("Replace body"));
  await user.type(screen.getByLabelText("Replacement body"), "edited");
  await user.click(screen.getByRole("button", { name: "Resume flow" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "No longer paused",
  );
  expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
    headers: [{ name: "X-Lab", value: "test" }],
    body: "edited",
  });
});
it("confirms drop/replay and exposes the complete replay result", async () => {
  const fetch = mock();
  const user = userEvent.setup();
  const nativeConfirm = vi.spyOn(window, "confirm");
  await renderAppReady(<FlowActions flow={flow} onChanged={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Drop flow" }));
  const dropDialog = screen.getByRole("alertdialog", {
    name: "Drop this paused flow and close its exchange?",
  });
  await user.click(within(dropDialog).getByRole("button", { name: "Cancel" }));
  expect(screen.queryByRole("alertdialog")).toBeNull();
  expect(fetch).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole("button", { name: "Drop flow" }));
  await user.keyboard("{Escape}");
  expect(fetch).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole("button", { name: "Drop flow" }));
  await user.click(
    within(screen.getByRole("alertdialog")).getByRole("button", { name: "Drop flow" }),
  );
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  expect(String(fetch.mock.calls[1]?.[0])).toBe("/v1/flows/one:drop");
  await user.click(screen.getByRole("button", { name: "Replay flow" }));
  await user.click(
    within(
      screen.getByRole("alertdialog", { name: "Replay this captured request once against its origin?" }),
    ).getByRole("button", { name: "Replay flow" }),
  );
  expect(
    await screen.findByRole("link", { name: "Inspect replay replayed" }),
  ).toHaveAttribute("href", "/flows/replayed");
  expect(screen.getByLabelText("Replay result")).toHaveTextContent('"request"');
  expect(nativeConfirm).not.toHaveBeenCalled();
});
it("explains that request-phase resume creates a new ID", async () => {
  mock();
  const view = await renderAppReady(
    <FlowActions flow={{ ...flow, pausedPhase: "request" }} onChanged={vi.fn()} />,
  );
  expect(screen.getByLabelText("Flow actions")).toHaveTextContent(
    "Request-phase resume forwards a completed capture under a new ID. This record stays open.",
  );
  expect(screen.getByRole("button", { name: "Resume flow" })).toHaveClass("primary");
  expect(screen.getByRole("button", { name: "Drop flow" })).toHaveClass("btn-danger");
  view.rerender(<FlowActions flow={flow} onChanged={vi.fn()} />);
  expect(screen.getByLabelText("Flow actions")).not.toHaveTextContent("new ID");
});
it("keeps problem code, retryability and the raw problem visible", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) =>
      String(input) === "/v1/session"
        ? json(200, sessionView())
        : json(409, {
            status: 409,
            code: "flow_not_paused",
            detail: "No longer paused",
            retryable: false,
            remediation: "Refresh the flow.",
          }),
    ),
  );
  const user = userEvent.setup();
  await renderAppReady(<FlowActions flow={flow} onChanged={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Resume flow" }));
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("No longer paused Remediation: Refresh the flow.");
  expect(alert).toHaveTextContent("code flow_not_paused");
  expect(alert).toHaveTextContent("retryable false");
  expect(alert).toHaveTextContent('"code": "flow_not_paused"');
});
it("hides mutations for readers", async () => {
  mock(["mitm.read"]);
  await renderAppReady(<FlowActions flow={flow} onChanged={vi.fn()} />);
  expect(
    screen.queryByRole("button", { name: "Resume flow" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Replay flow" }),
  ).not.toBeInTheDocument();
});
it("ignores an action completion after switching to another flow", async () => {
  let resolve!: (response: Response) => void;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) =>
      String(input) === "/v1/session"
        ? json(200, sessionView())
        : new Promise<Response>((r) => {
            resolve = r;
          }),
    ),
  );
  const user = userEvent.setup();
  const changed = vi.fn();
  const view = await renderAppReady(
    <FlowActions key="one" flow={flow} onChanged={changed} />,
  );
  await user.click(screen.getByRole("button", { name: "Resume flow" }));
  view.rerender(
    <FlowActions key="two" flow={{ ...flow, id: "two" }} onChanged={changed} />,
  );
  resolve(new Response(null, { status: 204 }));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Resume flow" })).toBeEnabled(),
  );
  expect(changed).not.toHaveBeenCalled();
});
it("copies the paused response headers and allows explicitly clearing them", async () => {
  const fetch = mock();
  const user = userEvent.setup();
  await renderAppReady(
    <FlowActions
      flow={{
        ...flow,
        response: {
          ...flow.response,
          headers: [{ name: "X-Captured", value: "original" }],
        },
      }}
      onChanged={vi.fn()}
    />,
  );
  await user.click(screen.getByLabelText("Replace headers"));
  await user.click(
    screen.getByRole("button", { name: "Copy captured headers" }),
  );
  expect(screen.getByLabelText("Header name 1")).toHaveValue("X-Captured");
  expect(screen.getByLabelText("Header value 1")).toHaveValue("original");
  await user.click(
    screen.getByRole("button", { name: "Clear replacement headers" }),
  );
  await user.click(screen.getByRole("button", { name: "Resume flow" }));
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
    headers: [],
  });
});
