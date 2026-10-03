import { afterEach, describe, expect, it, vi } from "vitest";
import { APIError, setMemoryCSRF } from "./client";
import {
  applyConfiguration,
  exportConfigurationJSON,
  exportConfigurationYAML,
  planConfiguration,
  validateConfiguration,
  type ReviewedChange,
} from "./configuration";
import { json, resetClientState } from "../test/render";
afterEach(() => {
  resetClientState();
  vi.unstubAllGlobals();
});
describe("configuration API wire contract", () => {
  it.each([
    [
      "replaceStoreCaps",
      {
        store: {
          maxFlows: 1,
          maxBytes: "1MiB",
          maxBodyBytes: "1KiB",
          fullPolicy: "reject",
        },
      },
    ],
    [
      "replaceAdmission",
      {
        admission: {
          maxSessions: 1,
          maxSessionsPerIP: 1,
          maxInFlight: 1,
          maxInFlightBytes: "1MiB",
          sessionTimeout: "10m",
          idleTimeout: "1m",
          headerTimeout: "10s",
          dialTimeout: "10s",
          upstreamTimeout: "1m",
          maxConcurrentStreams: 1,
        },
      },
    ],
    [
      "replaceTLS",
      {
        tls: {
          intercept: true,
          hosts: [],
          ports: [443],
          ca: { mode: "files", certFile: "/lab/cert", keyFile: "/lab/key" },
          upstream: { insecureSkipVerify: false, extraCAFiles: [] },
        },
      },
    ],
    ["replaceRules", { rules: { enabled: false, items: [] } }],
    [
      "replaceTargets",
      {
        targets: {
          denyCloudMetadata: true,
          denyLinkLocal: true,
          allowLoopback: true,
          allowHosts: [],
          denyHosts: [],
        },
      },
    ],
    [
      "replaceCompat",
      { compat: { flowREST: { enabled: true, pathPrefix: "/compat" } } },
    ],
    ["setFeature", { feature: { id: "ui.enabled", enabled: true } }],
    ["replaceHTTPAuth", { httpAuth: { enabled: false, realm: "", users: [] } }],
  ])(
    "preserves every %s input in identical plan and apply bodies",
    async (op, payload) => {
      const fetchMock = vi.fn(
        async (_input: RequestInfo | URL, _init?: RequestInit) =>
          json(200, { diff: [], warnings: [] }),
      );
      vi.stubGlobal("fetch", fetchMock);
      setMemoryCSRF("csrf-test");
      const change: ReviewedChange = {
        expectedRevision: "sha256:abc",
        idempotencyKey: "key",
        reason: "",
        force: true,
        operations: [{ op: op as string, ...(payload as object) }],
      };
      await planConfiguration(change);
      await applyConfiguration(change);
      expect(fetchMock.mock.calls.map((call) => String(call[0]))).toEqual([
        "/v1/changes:plan",
        "/v1/changes:apply",
      ]);
      for (const call of fetchMock.mock.calls) {
        expect(JSON.parse(String(call[1]?.body))).toEqual(change);
        expect(call[1]?.method).toBe("POST");
        expect(call[1]?.credentials).toBe("same-origin");
        expect(new Headers(call[1]?.headers).get("X-LabMITM-CSRF")).toBe(
          "csrf-test",
        );
      }
    },
  );
  it("supports candidate plus operations validation and deterministic field errors", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        json(422, {
          status: 422,
          code: "validation_failed",
          detail: "invalid",
          fieldViolations: [
            {
              path: "state.spec.store.maxBytes",
              code: "invalid_value",
              message: "too small",
            },
          ],
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const input = {
      state: { spec: {} },
      operations: [
        { op: "replaceRules", rules: { enabled: false, items: [] } },
      ],
    };
    try {
      await validateConfiguration(input);
      expect.fail("expected validation failure");
    } catch (error) {
      expect(error).toBeInstanceOf(APIError);
      expect((error as APIError).problem.code).toBe("validation_failed");
      expect((error as APIError).problem.fieldViolations).toEqual([
        {
          path: "state.spec.store.maxBytes",
          code: "invalid_value",
          message: "too small",
        },
      ]);
    }
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual(
      input,
    );
  });
  it("returns canonical YAML text and JSON metadata and rejects export errors", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) =>
      String(input).endsWith("yaml")
        ? new Response("spec: {}\n")
        : json(200, {
            format: "json",
            revision: "sha256:a",
            bootstrapRevision: "sha256:b",
            drifted: true,
            humanDiff: "diff",
            body: { spec: {} },
          }),
    );
    vi.stubGlobal("fetch", fetchMock);
    expect(await exportConfigurationYAML()).toBe("spec: {}\n");
    expect(await exportConfigurationJSON()).toMatchObject({
      drifted: true,
      humanDiff: "diff",
    });
    fetchMock.mockImplementation(async () =>
      json(403, { status: 403, code: "forbidden", detail: "admin required" }),
    );
    await expect(exportConfigurationYAML()).rejects.toBeInstanceOf(APIError);
  });
});
