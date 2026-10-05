import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CSRF_HEADER } from "../api/client";
import {
  json,
  renderAppReady,
  resetClientState,
  sessionView,
} from "../test/render";
import { sampleState } from "../test/state";
import {
  CONFIGURATION_OPERATIONS,
  ConfigurationPage,
} from "./ConfigurationPage";
const plan = {
  previousRevision: "sha256:abc",
  candidateRevision: "sha256:next",
  drifted: true,
  diff: [
    { path: "spec.tls.hosts", op: "replace", before: [], after: ["lab.test"] },
  ],
  warnings: [{ code: "live_next_connection", message: "New sessions only" }],
};
function fixture(scopes?: string[], conflict = false, conflictCode = "revision_conflict") {
  let revision = "sha256:abc";
  const state = sampleState();
  const canonical = state.canonical! as unknown as Record<string, unknown>;
  const spec = canonical.spec as Record<string, unknown>;
  (spec.proxy as Record<string, unknown>).targets = {
    denyCloudMetadata: true,
    denyLinkLocal: true,
    allowLoopback: true,
    allowHosts: [],
    denyHosts: [],
  };
  spec.store = {
    maxFlows: 1000,
    maxBytes: "256MiB",
    maxBodyBytes: "1MiB",
    fullPolicy: "reject",
    spillDirectory: "",
    spillThreshold: "256KiB",
    maxWait: "60s",
  };
  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, _init?: RequestInit) => {
      const url = String(input);
      if (url === "/v1/session") return json(200, sessionView(scopes));
      if (url === "/v1/state")
        return json(200, { ...state, runtimeRevision: revision });
      if (url === "/v1/changes:apply") {
        revision = "sha256:newer";
        return conflict
          ? json(409, {
              status: 409,
              code: conflictCode,
              detail: "Revision changed",
              fields: [{ path: "expectedRevision", message: "stale" }],
            })
          : json(200, {
              ...plan,
              applied: true,
              runtimeRevision: "sha256:next",
              generation: 5,
            });
      }
      if (url === "/v1/changes:plan" || url === "/v1/state:validate")
        return json(200, { ...plan, previousRevision: revision });
      if (url === "/v1/state:export?format=json")
        return json(200, {
          format: "json",
          revision,
          bootstrapRevision: "sha256:boot",
          drifted: true,
          body: canonical,
          humanDiff: "spec.tls.hosts changed",
        });
      if (url === "/v1/state:export?format=yaml")
        return new Response(
          "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\n",
          {
            headers: {
              "Content-Type": "application/yaml",
              "X-LabMITM-Revision": revision,
            },
          },
        );
      return json(404, {});
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  return { fetchMock, state };
}
async function selectTab(label: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole("tab", { name: label }));
  });
}
function chooseTemplate(operation: string) {
  fireEvent.click(
    within(screen.getByRole("group", { name: "Operation template" })).getByRole("button", {
      name: new RegExp(`^${operation}\\b`),
    }),
  );
}
async function confirmDialog(name: RegExp | string, accept: boolean) {
  const dialog = await screen.findByRole("alertdialog", { name });
  await act(async () => {
    fireEvent.click(
      within(dialog).getAllByRole("button")[accept ? 1 : 0]!,
    );
  });
  return dialog;
}
async function click(label: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: label }));
  });
}
function body(mock: ReturnType<typeof fixture>["fetchMock"], path: string) {
  return JSON.parse(
    String(mock.mock.calls.find((call) => String(call[0]) === path)?.[1]?.body),
  );
}
afterEach(() => {
  resetClientState();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
const initial: Record<string, unknown> = {
  replaceStoreCaps: {
    op: "replaceStoreCaps",
    store: {
      maxFlows: 1000,
      maxBytes: "256MiB",
      maxBodyBytes: "1MiB",
      fullPolicy: "reject",
    },
  },
  replaceAdmission: {
    op: "replaceAdmission",
    admission: {
      maxSessions: 256,
      maxSessionsPerIP: 32,
      maxInFlight: 64,
      maxInFlightBytes: "64MiB",
      sessionTimeout: "10m",
      idleTimeout: "120s",
      headerTimeout: "10s",
      dialTimeout: "10s",
      upstreamTimeout: "60s",
      maxConcurrentStreams: 100,
    },
  },
  replaceTLS: {
    op: "replaceTLS",
    tls: {
      intercept: true,
      hosts: [],
      ports: [443],
      ca: { mode: "generate", certFile: "", keyFile: "" },
      upstream: { insecureSkipVerify: false, extraCAFiles: [] },
    },
  },
  replaceRules: { op: "replaceRules", rules: { enabled: false, items: [] } },
  replaceTargets: {
    op: "replaceTargets",
    targets: {
      denyCloudMetadata: true,
      denyLinkLocal: true,
      allowLoopback: true,
      allowHosts: [],
      denyHosts: [],
    },
  },
  replaceCompat: {
    op: "replaceCompat",
    compat: { flowREST: { enabled: false, pathPrefix: "/compat" } },
  },
  setFeature: {
    op: "setFeature",
    feature: { id: "protocols.http2", enabled: false },
  },
  replaceHTTPAuth: {
    op: "replaceHTTPAuth",
    httpAuth: { enabled: false, realm: "labmitm-proxy", users: [] },
  },
};
const edited: Record<string, unknown> = {
  replaceStoreCaps: {
    op: "replaceStoreCaps",
    store: {
      maxFlows: 222,
      maxBytes: "64MiB",
      maxBodyBytes: "64KiB",
      fullPolicy: "evict_oldest",
    },
  },
  replaceAdmission: {
    op: "replaceAdmission",
    admission: {
      maxSessions: 32,
      maxSessionsPerIP: 8,
      maxInFlight: 16,
      maxInFlightBytes: "32MiB",
      sessionTimeout: "3m",
      idleTimeout: "90s",
      headerTimeout: "20s",
      dialTimeout: "5s",
      upstreamTimeout: "120s",
      maxConcurrentStreams: 20,
    },
  },
  replaceTLS: {
    op: "replaceTLS",
    tls: {
      intercept: false,
      hosts: ["lab.test"],
      ports: [8443],
      ca: { mode: "files", certFile: "/lab/cert", keyFile: "/lab/key" },
      upstream: { insecureSkipVerify: true, extraCAFiles: ["/lab/extra"] },
    },
  },
  replaceRules: {
    op: "replaceRules",
    rules: {
      enabled: true,
      items: [
        {
          id: "pause-login",
          enabled: true,
          phase: "request",
          match: { host: "lab.test" },
          action: { type: "breakpoint" },
        },
      ],
    },
  },
  replaceTargets: {
    op: "replaceTargets",
    targets: {
      denyCloudMetadata: false,
      denyLinkLocal: false,
      allowLoopback: false,
      allowHosts: ["lab.test"],
      denyHosts: ["deny.test"],
    },
  },
  replaceCompat: {
    op: "replaceCompat",
    compat: { flowREST: { enabled: true, pathPrefix: "/labcompat" } },
  },
  setFeature: {
    op: "setFeature",
    feature: { id: "protocols.websocket", enabled: false },
  },
  replaceHTTPAuth: {
    op: "replaceHTTPAuth",
    httpAuth: {
      enabled: true,
      realm: "Lab",
      users: [
        { id: "qa", usernameFile: "/lab/user", passwordFile: "/lab/pass" },
      ],
    },
  },
};
describe("ConfigurationPage", () => {
  let nativeConfirm: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    nativeConfirm = vi.spyOn(window, "confirm");
  });
  afterEach(() => {
    expect(nativeConfirm).not.toHaveBeenCalled();
  });
  it.each(CONFIGURATION_OPERATIONS)(
    "initializes and validates every field for %s",
    async (operation) => {
      const { fetchMock } = fixture();
      await renderAppReady(<ConfigurationPage />);
      chooseTemplate(operation);
      expect(
        JSON.parse(
          (screen.getByLabelText("Operations JSON") as HTMLTextAreaElement)
            .value,
        ),
      ).toEqual([initial[operation]]);
      await click("Validate operations");
      expect(body(fetchMock, "/v1/state:validate")).toEqual({
        operations: [initial[operation]],
      });
      expect(screen.getByRole("status")).toHaveTextContent(
        "live_next_connection",
      );
      fireEvent.change(screen.getByLabelText("Operations JSON"), {
        target: { value: JSON.stringify([edited[operation]]) },
      });
      await click("Plan changes");
      await click("Apply reviewed changes");
      expect(body(fetchMock, "/v1/changes:plan").operations).toEqual([
        edited[operation],
      ]);
      expect(body(fetchMock, "/v1/changes:apply").operations).toEqual([
        edited[operation],
      ]);
    },
  );
  it("pins the reviewed payload, revision, reason, force and key through apply", async () => {
    const { fetchMock } = fixture();
    await renderAppReady(<ConfigurationPage />);
    const operations = [
      {
        op: "replaceTLS",
        tls: {
          intercept: true,
          hosts: ["lab.test"],
          ports: [8443],
          ca: {
            mode: "files",
            certFile: "/lab/ca.pem",
            keyFile: "/lab/key.pem",
          },
          upstream: {
            insecureSkipVerify: true,
            extraCAFiles: ["/lab/upstream.pem"],
          },
        },
      },
      {
        op: "replaceTargets",
        targets: {
          denyCloudMetadata: true,
          denyLinkLocal: true,
          allowLoopback: true,
          allowHosts: [],
          denyHosts: [],
        },
      },
    ];
    fireEvent.change(screen.getByLabelText("Operations JSON"), {
      target: { value: JSON.stringify(operations) },
    });
    fireEvent.change(screen.getByLabelText("Reason (optional)"), {
      target: { value: "lab update" },
    });
    fireEvent.change(
      screen.getByLabelText("Idempotency key (optional; generated for plan)"),
      { target: { value: "reviewed-key" } },
    );
    fireEvent.click(screen.getByLabelText("Force store shrink eviction"));
    await click("Plan changes");
    expect(
      fetchMock.mock.calls.some(
        (call) => String(call[0]) === "/v1/changes:apply",
      ),
    ).toBe(false);
    expect(screen.getByText("Review planned changes")).toBeVisible();
    await click("Apply reviewed changes");
    const planned = body(fetchMock, "/v1/changes:plan");
    expect(body(fetchMock, "/v1/changes:apply")).toEqual(planned);
    expect(planned).toEqual({
      expectedRevision: "sha256:abc",
      idempotencyKey: "reviewed-key",
      reason: "lab update",
      force: true,
      operations,
    });
    const call = fetchMock.mock.calls.find(
      (row) => String(row[0]) === "/v1/changes:apply",
    );
    expect(new Headers(call?.[1]?.headers).get(CSRF_HEADER)).toBe("csrf-test");
    expect(call?.[1]?.credentials).toBe("same-origin");
    expect(screen.getByRole("status")).toHaveTextContent('"applied": true');
  });
  it("invalidates a plan when any reviewed input changes", async () => {
    fixture();
    await renderAppReady(<ConfigurationPage />);
    await click("Plan changes");
    const stepState = (label: string) =>
      Array.from(document.querySelectorAll("li[data-state]"))
        .find((li) => li.textContent?.endsWith(label))
        ?.getAttribute("data-state");
    // Planning without "Validate operations" must not mark Validate done.
    expect(stepState("Review plan")).toBe("current");
    expect(stepState("Validate")).toBe("todo");
    fireEvent.change(screen.getByLabelText("Reason (optional)"), {
      target: { value: "changed" },
    });
    expect(
      screen.queryByRole("button", { name: "Apply reviewed changes" }),
    ).toBeNull();
  });
  it("refreshes a conflict and requires a new explicit plan without retrying apply", async () => {
    const { fetchMock } = fixture(undefined, true);
    await renderAppReady(<ConfigurationPage />);
    await click("Plan changes");
    await click("Apply reviewed changes");
    expect(screen.getByRole("alert")).toHaveTextContent("plan again");
    expect(screen.getByRole("alert")).toHaveTextContent("Runtime changed");
    expect(
      screen.queryByRole("button", { name: "Apply reviewed changes" }),
    ).toBeNull();
    expect(
      fetchMock.mock.calls.filter(
        (call) => String(call[0]) === "/v1/changes:apply",
      ),
    ).toHaveLength(1);
    await click("Plan changes");
    const calls = fetchMock.mock.calls.filter(
      (call) => String(call[0]) === "/v1/changes:plan",
    );
    expect(JSON.parse(String(calls.at(-1)?.[1]?.body)).expectedRevision).toBe(
      "sha256:newer",
    );
  });
  it("validates full candidate state including explicit empty edits", async () => {
    const { fetchMock } = fixture();
    await renderAppReady(<ConfigurationPage />);
    const candidate = {
      apiVersion: "labmitm.dev/v1alpha1",
      kind: "LabMITM",
      metadata: { name: "" },
      spec: {
        listeners: { proxy: { address: "" } },
        tls: { hosts: [], ports: [] },
      },
    };
    fireEvent.change(screen.getByLabelText("Candidate state JSON"), {
      target: { value: JSON.stringify(candidate) },
    });
    await selectTab("Validate candidate");
    await click("Validate candidate state");
    expect(body(fetchMock, "/v1/state:validate")).toEqual({ state: candidate });
  });
  it("does not mark the Validate step done after candidate-state validation", async () => {
    const { fetchMock } = fixture();
    await renderAppReady(<ConfigurationPage />);
    fireEvent.change(screen.getByLabelText("Candidate state JSON"), {
      target: { value: JSON.stringify({ apiVersion: "labmitm.dev/v1alpha1", kind: "LabMITM", spec: {} }) },
    });
    await selectTab("Validate candidate");
    await click("Validate candidate state");
    await waitFor(() => expect(fetchMock.mock.calls.some(([u]) => String(u) === "/v1/state:validate")).toBe(true));
    const step = Array.from(document.querySelectorAll("li[data-state]")).find((li) =>
      li.textContent?.endsWith("Validate"),
    );
    expect(step?.getAttribute("data-state")).not.toBe("done");
  });
  it.each(["JSON", "YAML"])(
    "exports %s with revisions, drift and human diff",
    async (format) => {
      fixture();
      await renderAppReady(<ConfigurationPage />);
      await selectTab("Export");
      await click(`Export ${format}`);
      const panel = screen.getByRole("tabpanel", { name: "Export" });
      expect(within(panel).getByText("spec.tls.hosts changed")).toBeVisible();
      expect(within(panel).getByText("sha256:boot")).toBeVisible();
      expect(
        (
          screen.getByLabelText(
            "Canonical export document",
          ) as HTMLTextAreaElement
        ).value,
      ).toContain(format === "YAML" ? "apiVersion:" : '"spec"');
    },
  );
  it("prevents invalid JSON from producing a request", async () => {
    const { fetchMock } = fixture();
    await renderAppReady(<ConfigurationPage />);
    fireEvent.change(screen.getByLabelText("Operations JSON"), {
      target: { value: "{" },
    });
    await click("Plan changes");
    expect(screen.getByRole("alert")).toBeVisible();
    expect(
      fetchMock.mock.calls.some(
        (call) => String(call[0]) === "/v1/changes:plan",
      ),
    ).toBe(false);
  });
  it("issues new automatic keys after edits, discard and successful apply", async () => {
    const { fetchMock } = fixture();
    await renderAppReady(<ConfigurationPage />);
    await click("Plan changes");
    const first = body(fetchMock, "/v1/changes:plan").idempotencyKey;
    fireEvent.change(screen.getByLabelText("Reason (optional)"), {
      target: { value: "edited" },
    });
    await click("Plan changes");
    let plans = fetchMock.mock.calls.filter(
      (call) => String(call[0]) === "/v1/changes:plan",
    );
    const second = JSON.parse(String(plans.at(-1)?.[1]?.body)).idempotencyKey;
    expect(second).not.toBe(first);
    await click("Discard plan");
    await click("Plan changes");
    plans = fetchMock.mock.calls.filter(
      (call) => String(call[0]) === "/v1/changes:plan",
    );
    const third = JSON.parse(String(plans.at(-1)?.[1]?.body)).idempotencyKey;
    expect(third).not.toBe(second);
    await click("Apply reviewed changes");
    await click("Plan changes");
    plans = fetchMock.mock.calls.filter(
      (call) => String(call[0]) === "/v1/changes:plan",
    );
    expect(JSON.parse(String(plans.at(-1)?.[1]?.body)).idempotencyKey).not.toBe(
      third,
    );
  });
  it("preserves an exact reviewed request after uncertain network failure", async () => {
    const { fetchMock } = fixture();
    await renderAppReady(<ConfigurationPage />);
    await click("Plan changes");
    const original = fetchMock.getMockImplementation()!;
    let failed = false;
    fetchMock.mockImplementation(async (input, init) => {
      if (String(input) === "/v1/changes:apply" && !failed) {
        failed = true;
        throw new Error("network lost");
      }
      return original(input, init);
    });
    await click("Apply reviewed changes");
    expect(screen.getByRole("alert")).toHaveTextContent("network lost");
    await click("Apply reviewed changes");
    const applies = fetchMock.mock.calls.filter(
      (call) => String(call[0]) === "/v1/changes:apply",
    );
    expect(applies).toHaveLength(2);
    expect(applies[0]?.[1]?.body).toBe(applies[1]?.[1]?.body);
  });
  it("requires inspector-off and destructive store confirmation", async () => {
    const { fetchMock } = fixture();
    await renderAppReady(<ConfigurationPage />);
    fireEvent.change(screen.getByLabelText("Operations JSON"), {
      target: {
        value: JSON.stringify([
          { op: "setFeature", feature: { id: "ui.enabled", enabled: false } },
        ]),
      },
    });
    await click("Plan changes");
    await click("Apply reviewed changes");
    const off = await confirmDialog("Disable the inspector?", false);
    expect(off).toHaveTextContent("404");
    expect(off).toHaveTextContent("REST/MCP remain available");
    expect(
      fetchMock.mock.calls.some(
        (call) => String(call[0]) === "/v1/changes:apply",
      ),
    ).toBe(false);
    chooseTemplate("replaceStoreCaps");
    fireEvent.click(screen.getByLabelText("Force store shrink eviction"));
    await click("Plan changes");
    await click("Apply reviewed changes");
    const evict = await confirmDialog("Apply the reviewed store change?", false);
    expect(evict).toHaveTextContent("permanently evict");
    expect(
      fetchMock.mock.calls.some(
        (call) => String(call[0]) === "/v1/changes:apply",
      ),
    ).toBe(false);
  });
  it("applies an inspector-off change only after the in-page confirm", async () => {
    const { fetchMock } = fixture();
    await renderAppReady(<ConfigurationPage />);
    fireEvent.change(screen.getByLabelText("Operations JSON"), {
      target: {
        value: JSON.stringify([
          { op: "setFeature", feature: { id: "ui.enabled", enabled: false } },
        ]),
      },
    });
    await click("Plan changes");
    const review = screen.getByRole("region", { name: "Review planned changes" });
    expect(within(review).getByRole("table", { name: "Planned diff" })).toHaveTextContent("spec.tls.hosts");
    expect(within(review).getByText("sha256:next")).toHaveAttribute("title", "sha256:next");
    expect(review).toHaveTextContent("live_next_connection");
    await click("Apply reviewed changes");
    await confirmDialog("Disable the inspector?", true);
    expect(
      fetchMock.mock.calls.filter((call) => String(call[0]) === "/v1/changes:apply"),
    ).toHaveLength(1);
    expect(screen.getByRole("status")).toHaveTextContent("Applied · revision sha256:next · generation 5");
  });
  it("rejects mismatched YAML revision metadata", async () => {
    const { fetchMock } = fixture();
    await renderAppReady(<ConfigurationPage />);
    const original = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation(async (input, init) =>
      String(input).endsWith("format=yaml")
        ? new Response("spec: {}", {
            headers: { "X-LabMITM-Revision": "sha256:other" },
          })
        : original(input, init),
    );
    await selectTab("Export");
    await click("Export YAML");
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Runtime changed during export",
    );
    expect(screen.queryByLabelText("Canonical export document")).toBeNull();
  });
  it("validates candidate with operations and refreshes state for readers", async () => {
    const { fetchMock } = fixture();
    await renderAppReady(<ConfigurationPage />);
    await selectTab("Validate candidate");
    expect(screen.getByRole("tabpanel", { name: "Validate candidate" })).toHaveTextContent(
      "1 op from Live changes",
    );
    await click("Validate candidate with operations");
    expect(body(fetchMock, "/v1/state:validate")).toHaveProperty(
      "state.spec.tls",
    );
    expect(body(fetchMock, "/v1/state:validate").operations).toHaveLength(1);
    await click("Refresh current state");
    expect(
      fetchMock.mock.calls.filter((call) => String(call[0]) === "/v1/state"),
    ).toHaveLength(2);
  });
  it("renders deterministic validation field violations and remediation", async () => {
    const { fetchMock } = fixture();
    await renderAppReady(<ConfigurationPage />);
    const original = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation(async (input, init) =>
      String(input) === "/v1/state:validate"
        ? json(422, {
            status: 422,
            code: "validation_failed",
            detail: "Invalid store capacity",
            fieldViolations: [
              {
                path: "store.maxBytes",
                code: "invalid_value",
                message: "must be at least 1MiB",
              },
            ],
            remediation: "Use IEC byte-size strings",
          })
        : original(input, init),
    );
    await click("Validate operations");
    expect(screen.getByRole("alert")).toHaveTextContent("store.maxBytes");
    expect(screen.getByRole("alert")).toHaveTextContent(
      "must be at least 1MiB",
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Use IEC byte-size strings",
    );
  });
  it("gates admin workflows for a reader", async () => {
    const { fetchMock } = fixture(["mitm.read"]);
    await renderAppReady(<ConfigurationPage />);
    const byTab: Record<string, string[]> = {
      "Live changes": ["Validate operations", "Plan changes", "Reset to current", "Add op"],
      "Validate candidate": ["Validate candidate state", "Validate candidate with operations"],
      Export: ["Export JSON", "Export YAML"],
    };
    for (const [tabName, labels] of Object.entries(byTab)) {
      await selectTab(tabName);
      for (const label of labels)
        expect(screen.getByRole("button", { name: label })).toBeDisabled();
    }
    await selectTab("Live changes");
    expect(screen.getByLabelText("Operations JSON")).toBeDisabled();
    expect(screen.getByLabelText("Candidate state JSON")).toBeDisabled();
    for (const template of within(
      screen.getByRole("group", { name: "Operation template" }),
    ).getAllByRole("button"))
      expect(template).toBeDisabled();
    expect(
      fetchMock.mock.calls.every(
        (call) => (call[1]?.method ?? "GET") === "GET",
      ),
    ).toBe(true);
  });
});

describe("ConfigurationPage conflict labels", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });
  it("labels idempotency conflicts by code and issues a new automatic key", async () => {
    const { fetchMock } = fixture(undefined, true, "idempotency_conflict");
    await renderAppReady(<ConfigurationPage />);
    await click("Plan changes");
    const first = body(fetchMock, "/v1/changes:plan").idempotencyKey;
    await click("Apply reviewed changes");
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("idempotency key was already used for a different request");
    expect(alert).toHaveTextContent("a new automatic key will be used");
    expect(alert).not.toHaveTextContent("Runtime changed");
    await click("Plan changes");
    const plans = fetchMock.mock.calls.filter(
      (call) => String(call[0]) === "/v1/changes:plan",
    );
    expect(JSON.parse(String(plans.at(-1)?.[1]?.body)).idempotencyKey).not.toBe(first);
  });
  it("names other conflict codes without claiming a revision change", async () => {
    fixture(undefined, true, "store_full");
    await renderAppReady(<ConfigurationPage />);
    await click("Plan changes");
    await click("Apply reviewed changes");
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Conflict (store_full)");
    expect(alert).not.toHaveTextContent("Runtime changed");
  });
});
