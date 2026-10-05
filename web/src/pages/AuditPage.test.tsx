import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  json,
  renderAppReady,
  resetClientState,
  sessionView,
} from "../test/render";
import * as Auth from "../auth/AuthProvider";
import { AuditPage } from "./AuditPage";

afterEach(() => {
  resetClientState();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
describe("AuditPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });
  it("shows an empty state when the ring is empty", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/audit")) {
          return json(200, { events: [] });
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
    await renderAppReady(<AuditPage />, { route: "/audit" });
    expect(
      await screen.findByRole("heading", { name: "Audit" }),
    ).toBeInTheDocument();
    expect(screen.getByText("No audit events.")).toBeInTheDocument();
    expect(document.querySelector(".panel")).not.toBeNull();
    expect(
      screen.queryByRole("button", { name: /fuzzer|repeater|exploit|relay/i }),
    ).toBeNull();
  });
  it("renders a row from GET /v1/audit events", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/audit")) {
          return json(200, {
            events: [
              {
                id: "aud_1",
                time: "2026-08-29T00:00:00Z",
                capability: "flows.delete",
                actorId: "admin",
                result: "ok",
                flowId: "01J",
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
    await renderAppReady(<AuditPage />, { route: "/audit" });
    const list = await screen.findByRole("list", { name: "Audit event list" });
    expect(within(list).getByText("flows.delete")).toBeInTheDocument();
    expect(within(list).getByText(/admin/)).toBeInTheDocument();
    expect(within(list).getByText("ok")).toHaveClass("chip-ok");
    expect(within(list).getByText(/flow 01J/)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /fuzzer|repeater|exploit|relay/i }),
    ).toBeNull();
  });
});
describe("Audit read parity", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });
  it("sends the limit and encoded event ID, shows complete escaped detail, clears stale detail on errors", async () => {
    const fetch = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path === "/v1/session") return json(200, sessionView());
      if (path.startsWith("/v1/audit?"))
        return json(200, {
          events: [{ id: "event/1", time: "now", capability: "state.apply" }],
        });
      if (path === "/v1/audit/event%2F1")
        return json(200, {
          id: "event/1",
          time: "now",
          actorClass: "human",
          previous: "old",
          revision: "new",
          reason: "<script>danger</script>",
          diff: [{ path: "spec.rules", op: "replace", before: [], after: [] }],
        });
      if (path === "/v1/audit/missing")
        return json(404, { detail: "audit event not found" });
      return json(200, { events: [] });
    });
    vi.stubGlobal("fetch", fetch);
    await renderAppReady(<AuditPage />);
    fireEvent.change(screen.getByLabelText("Limit"), {
      target: { value: "7" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Refresh audit" }));
    fireEvent.click(await screen.findByRole("button", { name: /event\/1/ }));
    expect(await screen.findByLabelText("Raw audit event JSON")).toHaveTextContent(
      '"actorClass": "human"',
    );
    expect(screen.getByLabelText("Raw audit event JSON")).toHaveTextContent('"diff"');
    expect(screen.getByRole("table", { name: "Audit diff" })).toHaveTextContent("spec.rules");
    expect(document.querySelector("main script")).toBeNull();
    expect(fetch).toHaveBeenCalledWith(
      "/v1/audit?limit=7",
      expect.objectContaining({ credentials: "same-origin" }),
    );
    expect(fetch).toHaveBeenCalledWith(
      "/v1/audit/event%2F1",
      expect.anything(),
    );
    fireEvent.change(screen.getByLabelText("Event ID"), {
      target: { value: "missing" },
    });
    expect(screen.queryByLabelText("Raw audit event JSON")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Find event" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "audit event not found",
    );
  });
  it("requires audit scope rather than read scope", async () => {
    const fetch = vi.fn(async () => json(200, sessionView(["mitm.read"])));
    vi.stubGlobal("fetch", fetch);
    await renderAppReady(<AuditPage />);
    expect(screen.getByRole("alert")).toHaveTextContent("mitm.audit.read");
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

it("ignores late detail after switching event IDs", async () => {
  let finish!: (response: Response) => void;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path === "/v1/session") return json(200, sessionView());
      if (path === "/v1/audit/old")
        return new Promise<Response>((resolve) => {
          finish = resolve;
        });
      if (path === "/v1/audit/new")
        return json(200, { id: "new", time: "now", reason: "new detail" });
      return json(200, { events: [] });
    }),
  );
  await renderAppReady(<AuditPage />);
  fireEvent.change(screen.getByLabelText("Event ID"), {
    target: { value: "old" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Find event" }));
  fireEvent.change(screen.getByLabelText("Event ID"), {
    target: { value: "new" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Find event" }));
  expect(await screen.findByLabelText("Raw audit event JSON")).toHaveTextContent("new detail");
  await act(async () => {
    finish(json(200, { id: "old", time: "then", reason: "old detail" }));
  });
  expect(screen.queryAllByText(/old detail/)).toHaveLength(0);
  expect(screen.getByLabelText("Raw audit event JSON")).toHaveTextContent("new detail");
});

it("clears detail loading and stale responses when audit permission is revoked and restored", async () => {
  let finish!: (response: Response) => void;
  let allowed = true;
  const session = sessionView();
  vi.spyOn(Auth, "useAuth").mockImplementation(() => ({
    state: { status: "signed_in", session },
    hasScope: () => allowed,
    login: async () => {},
    logout: async () => {},
  }));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      if (String(input) === "/v1/audit/old")
        return new Promise<Response>((resolve) => {
          finish = resolve;
        });
      if (String(input) === "/v1/audit/new")
        return json(200, { id: "new", time: "now", reason: "fresh detail" });
      return json(200, { events: [] });
    }),
  );
  const view = render(<AuditPage />);
  fireEvent.change(screen.getByLabelText("Event ID"), {
    target: { value: "old" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Find event" }));
  expect(screen.getByRole("button", { name: "Find event" })).toBeDisabled();
  allowed = false;
  view.rerender(<AuditPage />);
  expect(screen.getByRole("alert")).toHaveTextContent("mitm.audit.read");
  allowed = true;
  view.rerender(<AuditPage />);
  expect(screen.getByLabelText("Event ID")).toHaveValue("");
  fireEvent.change(screen.getByLabelText("Event ID"), {
    target: { value: "new" },
  });
  expect(screen.getByRole("button", { name: "Find event" })).toBeEnabled();
  fireEvent.click(screen.getByRole("button", { name: "Find event" }));
  expect(await screen.findByLabelText("Raw audit event JSON")).toHaveTextContent("fresh detail");
  await act(async () => {
    finish(json(200, { id: "old", time: "then", reason: "stale detail" }));
  });
  expect(screen.queryAllByText(/stale detail/)).toHaveLength(0);
});

it("shows audit query field violations instead of only the detail", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) =>
      String(input).endsWith("/v1/session")
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
  await renderAppReady(<AuditPage />, { route: "/audit" });
  expect(await screen.findByRole("alert")).toHaveTextContent('reason: unknown field "reason" [unknown_field]');
});

it("filters loaded events by capability family and result chips together, client-side", async () => {
  const fetch = vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path === "/v1/session") return json(200, sessionView());
    return json(200, {
      events: [
        { id: "a1", time: "2026-10-03T21:49:07Z", capability: "changes.apply", result: "ok" },
        { id: "a2", time: "2026-10-03T21:49:11Z", capability: "changes.apply", result: "denied" },
        { id: "a3", time: "2026-10-03T21:52:22Z", capability: "flows.resume", result: "ok" },
        { id: "a4", time: "2026-10-03T21:53:00Z", capability: "flows.drop", result: "error" },
      ],
    });
  });
  vi.stubGlobal("fetch", fetch);
  await renderAppReady(<AuditPage />);
  const list = await screen.findByRole("list", { name: "Audit event list" });
  expect(within(list).getAllByRole("listitem")).toHaveLength(4);
  const caps = screen.getByRole("group", { name: "Filter by capability" });
  expect(within(caps).getByRole("button", { name: "changes.apply 2" })).toBeInTheDocument();
  fireEvent.click(within(caps).getByRole("button", { name: "flows.* 2" }));
  expect(within(list).getAllByRole("listitem")).toHaveLength(2);
  fireEvent.click(screen.getByRole("button", { name: "not ok 1" }));
  expect(within(list).getAllByRole("listitem")).toHaveLength(1);
  expect(within(list).getByText("error")).toHaveClass("chip-danger");
  fireEvent.click(within(caps).getByRole("button", { name: "All 4" }));
  expect(within(list).getAllByRole("listitem")).toHaveLength(2);
  expect(within(list).getByText("denied")).toHaveClass("chip-warn");
  expect(fetch.mock.calls.filter(([p]) => String(p).startsWith("/v1/audit"))).toHaveLength(1);
});
