import { afterEach, describe, expect, it, vi } from "vitest";
import { APIError } from "./client";
import {
  diagnosticReads,
  getAudit,
  getDiagnostic,
  queryAudit,
} from "./diagnostics";
import { json, resetClientState } from "../test/render";
afterEach(() => {
  resetClientState();
  vi.unstubAllGlobals();
});
describe("diagnostic wire contracts", () => {
  it("uses OpenMetrics accept and preserves text", async () => {
    const fetch = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response("metric 1\n# EOF\n"),
    );
    vi.stubGlobal("fetch", fetch);
    expect(await getDiagnostic(diagnosticReads[5])).toBe("metric 1\n# EOF\n");
    const init = fetch.mock.calls[0]?.[1] as RequestInit | undefined;
    expect(new Headers(init?.headers).get("Accept")).toBe(
      "application/openmetrics-text",
    );
  });
  it("preserves zero limit and escapes arbitrary event IDs", async () => {
    const fetch = vi.fn(async () => json(200, { events: [] }));
    vi.stubGlobal("fetch", fetch);
    await queryAudit(0);
    await getAudit("event/?#");
    expect(fetch).toHaveBeenCalledWith("/v1/audit?limit=0", expect.anything());
    expect(fetch).toHaveBeenCalledWith(
      "/v1/audit/event%2F%3F%23",
      expect.anything(),
    );
  });
  it("keeps structured server failures for read errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        json(403, { status: 403, code: "forbidden", detail: "audit denied" }),
      ),
    );
    await expect(getAudit("id")).rejects.toBeInstanceOf(APIError);
    await expect(queryAudit()).rejects.toMatchObject({
      problem: { code: "forbidden", status: 403 },
    });
  });
});
