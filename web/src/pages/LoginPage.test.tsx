import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, renderApp, resetClientState } from "../test/render";
import { LoginPage } from "./LoginPage";

describe("LoginPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("signs in with a token and never stores it", async () => {
    const user = userEvent.setup();
    let signedIn = false;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/v1/session") && method === "POST") {
        signedIn = true;
        return json(200, { csrf: "csrf-1", expiresAt: "2099-01-01T00:00:00Z" });
      }
      if (url.includes("/v1/session") && method === "GET") {
        if (!signedIn) {
          return json(401, {
            status: 401,
            title: "unauthenticated",
            detail: "authentication required",
            code: "unauthenticated",
            type: "urn:labmitm:error:unauthenticated",
          });
        }
        return json(200, {
          id: "admin",
          role: "administrator",
          scopes: ["mitm.read"],
          csrf: "csrf-1",
          expiresAt: "2099-01-01T00:00:00Z",
        });
      }
      return json(404, {
        status: 404,
        title: "not found",
        detail: "not found",
        code: "not_found",
        type: "urn:labmitm:error:not-found",
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderApp(<LoginPage />, { route: "/login" });
    const field = await screen.findByLabelText(/API bearer token/i);
    await user.type(field, "lab-bootstrap-token-32-bytes!!!");
    await user.keyboard("{Enter}");

    await waitFor(() => {
      expect(fetchMock.mock.calls.some((c) => (c[1]?.method ?? "GET").toUpperCase() === "POST")).toBe(true);
    });
    expect(screen.queryByRole("alert")).toBeNull();
    const post = fetchMock.mock.calls.find((c) => (c[1]?.method ?? "GET").toUpperCase() === "POST");
    expect(new Headers(post?.[1]?.headers).get("Authorization")).toBe("Bearer lab-bootstrap-token-32-bytes!!!");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(screen.queryByLabelText(/Username and password/i)).toBeNull();
  });

  it("shows an error when the token is empty", async () => {
    const user = userEvent.setup();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        json(401, {
          status: 401,
          title: "unauthenticated",
          detail: "authentication required",
          code: "unauthenticated",
          type: "urn:labmitm:error:unauthenticated",
        }),
      ),
    );
    renderApp(<LoginPage />, { route: "/login" });
    await screen.findByLabelText(/API bearer token/i);
    await user.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/enter an api bearer token/i);
  });
});
