import { afterEach, expect, it, vi } from "vitest";
import { clearFlows, deleteFlow, listAllFlows, setMemoryCSRF } from "./client";
import { json, resetClientState } from "../test/render";
afterEach(() => {
  resetClientState();
  vi.unstubAllGlobals();
});
it("walks past sixteen pages preserving all supported filters", async () => {
  let page = 0;
  const fetch = vi.fn(async (_input: RequestInfo | URL) =>
    json(200, {
      items: [{ id: String(page++) }],
      storeGeneration: 2,
      revision: "rev",
      nextCursor: page < 18 ? String(page) : null,
    }),
  );
  vi.stubGlobal("fetch", fetch);
  const query = {
    host: "lab",
    method: "GET",
    status: "200",
    scheme: "http",
    intercepted: "false",
    ruleId: "rule",
    pathPrefix: "/",
    protocol: "h2",
    via: "socks5",
  };
  const result = await listAllFlows(query);
  expect(result.items).toHaveLength(18);
  expect(result.nextCursor).toBeNull();
  for (const call of fetch.mock.calls)
    for (const [key, value] of Object.entries(query))
      expect(
        new URL(String(call[0]), "http://localhost").searchParams.get(key),
      ).toBe(value);
});
it("sends optional zero generation and CSRF for delete and clear", async () => {
  setMemoryCSRF("csrf");
  const fetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
    json(200, { deleted: 1 }),
  );
  vi.stubGlobal("fetch", fetch);
  await deleteFlow("id", 0);
  await clearFlows(12);
  await deleteFlow("id");
  expect(fetch.mock.calls.map((c) => String(c[0]))).toEqual([
    "/v1/flows/id?expectedStoreGeneration=0",
    "/v1/flows?expectedStoreGeneration=12",
    "/v1/flows/id",
  ]);
  expect(
    new Headers(fetch.mock.calls[0]?.[1]?.headers).get("X-LabMITM-CSRF"),
  ).toBe("csrf");
});
it("preserves structured server problems for operators", async () => {
  const problem = {
    type: "urn:labmitm:error:validation_failed",
    title: "Validation failed",
    status: 400,
    code: "validation_failed",
    detail: "Invalid patch",
    instance: "/v1/flows/id:resume",
    retryable: false,
    fieldViolations: [
      {
        path: "headers.0.name",
        code: "invalid_value",
        message: "Invalid header name",
      },
    ],
    currentRevision: "revision",
    remediation: "Fix the field",
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => json(400, problem)),
  );
  const { resumeFlow } = await import("./client");
  await expect(
    resumeFlow("id", { headers: [{ name: "", value: "" }] }),
  ).rejects.toMatchObject({ problem });
});
