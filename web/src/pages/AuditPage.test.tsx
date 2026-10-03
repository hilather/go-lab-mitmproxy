import { act, fireEvent, render, screen } from "@testing-library/react";
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
    expect(await screen.findByText("flows.delete")).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
    expect(screen.getByText("ok")).toBeInTheDocument();
    expect(screen.getByText("01J")).toBeInTheDocument();
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
    fireEvent.click(await screen.findByRole("button", { name: "event/1" }));
    expect(await screen.findByText(/"actorClass": "human"/)).toHaveTextContent(
      '"diff"',
    );
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
    expect(screen.queryByText(/"actorClass"/)).toBeNull();
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
  expect(await screen.findByText(/new detail/)).toBeInTheDocument();
  await act(async () => {
    finish(json(200, { id: "old", time: "then", reason: "old detail" }));
  });
  expect(screen.queryByText(/old detail/)).toBeNull();
  expect(screen.getByText(/new detail/)).toBeInTheDocument();
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
  expect(await screen.findByText(/fresh detail/)).toBeInTheDocument();
  await act(async () => {
    finish(json(200, { id: "old", time: "then", reason: "stale detail" }));
  });
  expect(screen.queryByText(/stale detail/)).toBeNull();
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
