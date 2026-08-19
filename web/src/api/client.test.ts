import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CSRF_HEADER,
  LIST_PAGE_LIMIT,
  apiFetch,
  bearerAuthorization,
  clearMemoryCSRF,
  createSession,
  listAllFlows,
  setMemoryCSRF,
} from "./client";
import { resetClientState } from "../test/render";

describe("API client", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("exchanges a bearer for a session without writing web storage", async () => {
    const fetchMock = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>(async () => {
      return new Response(JSON.stringify({ csrf: "csrf-1", expiresAt: "2099-01-01T00:00:00Z" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const created = await createSession(bearerAuthorization("lab-bootstrap-token-32-bytes!!!"));
    expect(created.csrf).toBe("csrf-1");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const init = fetchMock.mock.calls[0]?.[1];
    if (!init) {
      throw new Error("expected fetch init");
    }
    expect(init.credentials).toBe("same-origin");
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer lab-bootstrap-token-32-bytes!!!");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("copies the in-memory CSRF secret onto mutating requests", async () => {
    setMemoryCSRF("csrf-test");
    const fetchMock = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>(
      async () => new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await apiFetch("/v1/session", { method: "DELETE" });
    const init = fetchMock.mock.calls[0]?.[1];
    if (!init) {
      throw new Error("expected fetch init");
    }
    expect(new Headers(init.headers).get(CSRF_HEADER)).toBe("csrf-test");
  });

  it("does not send CSRF on GET", async () => {
    setMemoryCSRF("csrf-test");
    const fetchMock = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>(
      async () => new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await apiFetch("/v1/flows");
    const init = fetchMock.mock.calls[0]?.[1];
    if (!init) {
      throw new Error("expected fetch init");
    }
    expect(new Headers(init.headers).has(CSRF_HEADER)).toBe(false);
    clearMemoryCSRF();
  });

  it("walks nextCursor so a 51st flow is not dropped", async () => {
    const page1 = Array.from({ length: 50 }, (_, i) => ({ id: `f${i + 1}`, method: "GET" }));
    const fetchMock = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>(async (input) => {
      const url = new URL(String(input), "http://lab.invalid");
      expect(url.searchParams.get("limit")).toBe(String(LIST_PAGE_LIMIT));
      if (!url.searchParams.get("cursor")) {
        return new Response(
          JSON.stringify({ revision: "r", storeGeneration: 2, items: page1, nextCursor: "cur-2" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      expect(url.searchParams.get("cursor")).toBe("cur-2");
      return new Response(
        JSON.stringify({
          revision: "r",
          storeGeneration: 2,
          items: [{ id: "f51", method: "GET" }],
          nextCursor: null,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const list = await listAllFlows();
    expect(list.items).toHaveLength(51);
    expect(list.items[50]?.id).toBe("f51");
    expect(list.nextCursor).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
