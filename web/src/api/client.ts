import { assertNoTokenStorage } from "./storage";
import type {
  ApplyResult,
  AuditList,
  ChangeSet,
  FeatureList,
  Flow,
  FlowList,
  FlowListQuery,
  Problem,
  SessionCreated,
  SessionView,
  StateView,
  Status,
} from "./types";

export const CSRF_HEADER = "X-LabMITM-CSRF";

export class APIError extends Error {
  readonly problem: Problem;

  constructor(problem: Problem) {
    super(problem.detail || problem.title || "request failed");
    this.name = "APIError";
    this.problem = problem;
  }
}

/**
 * problemMessage renders a problem+json error as one operator-facing line:
 * the detail, then every field violation, then remediation when present.
 */
export function problemMessage(problem: Problem): string {
  let text = problem.detail || problem.title || "request failed";
  const violations = problem.fieldViolations ?? [];
  if (violations.length > 0) {
    text += ` (${violations
      .map((v) => `${v.path || "(body)"}: ${v.message} [${v.code}]`)
      .join("; ")})`;
  }
  if (problem.remediation) text += ` Remediation: ${problem.remediation}`;
  return text;
}

/** errorMessage prefers the full problem text for API errors. */
export function errorMessage(err: unknown, fallback: string, anyError = false): string {
  if (err instanceof APIError) return problemMessage(err.problem);
  if (anyError && err instanceof Error) return err.message;
  return fallback;
}

let memoryCSRF = "";

export function setMemoryCSRF(value: string): void {
  memoryCSRF = value;
}

export function getMemoryCSRF(): string {
  return memoryCSRF;
}

export function clearMemoryCSRF(): void {
  memoryCSRF = "";
}

function problemFrom(status: number, statusText: string, body: unknown): Problem {
  const fallback: Problem = {
    type: "urn:labmitm:error:internal-error",
    title: statusText || "error",
    status,
    detail: statusText || "request failed",
    code: status === 401 ? "unauthenticated" : status === 403 ? "forbidden" : "internal_error",
  };
  if (!body || typeof body !== "object") {
    return fallback;
  }
  const rec = body as Record<string, unknown>;
  return {
    type: typeof rec.type === "string" ? rec.type : fallback.type,
    title: typeof rec.title === "string" ? rec.title : fallback.title,
    status: typeof rec.status === "number" ? rec.status : fallback.status,
    detail: typeof rec.detail === "string" ? rec.detail : fallback.detail,
    code: typeof rec.code === "string" ? rec.code : fallback.code,
    ...(typeof rec.instance === "string" ? { instance: rec.instance } : {}),
    ...(typeof rec.retryable === "boolean" ? { retryable: rec.retryable } : {}),
    ...(Array.isArray(rec.fieldViolations) ? { fieldViolations: rec.fieldViolations.filter((value): value is { path: string; code: string; message: string } => !!value && typeof value === "object" && typeof value.path === "string" && typeof value.code === "string" && typeof value.message === "string") } : {}),
    ...(typeof rec.currentRevision === "string" ? { currentRevision: rec.currentRevision } : {}),
    ...(typeof rec.remediation === "string" ? { remediation: rec.remediation } : {}),
  };
}

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  assertNoTokenStorage();
  const headers = new Headers(init.headers);
  const method = (init.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD" && !headers.has(CSRF_HEADER)) {
    const csrf = getMemoryCSRF();
    if (csrf !== "") {
      headers.set(CSRF_HEADER, csrf);
    }
  }
  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }
  return fetch(path, {
    ...init,
    credentials: "same-origin",
    headers,
  });
}

export async function readJSON<T>(resp: Response): Promise<T> {
  const text = await resp.text();
  let parsed: unknown;
  if (text !== "") {
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      parsed = undefined;
    }
  }
  if (!resp.ok) {
    throw new APIError(problemFrom(resp.status, resp.statusText, parsed));
  }
  return parsed as T;
}

export async function createSession(authorization: string): Promise<SessionCreated> {
  const resp = await apiFetch("/v1/session", {
    method: "POST",
    headers: { Authorization: authorization },
  });
  const created = await readJSON<SessionCreated>(resp);
  setMemoryCSRF(created.csrf);
  assertNoTokenStorage();
  return created;
}

export function bearerAuthorization(token: string): string {
  return `Bearer ${token}`;
}

export async function getSession(): Promise<SessionView> {
  const view = await readJSON<SessionView>(await apiFetch("/v1/session"));
  if (typeof view.csrf === "string" && view.csrf !== "") {
    setMemoryCSRF(view.csrf);
  }
  return view;
}

export async function deleteSession(): Promise<void> {
  const resp = await apiFetch("/v1/session", { method: "DELETE" });
  if (resp.status === 401 || resp.status === 204) {
    clearMemoryCSRF();
    return;
  }
  await readJSON<unknown>(resp);
  clearMemoryCSRF();
}

// Native list default is 50; the store cap is 1000. Walk at MaxListLimit so
// the inspector is not silently truncated to the first page.
export const LIST_PAGE_LIMIT = 200;


function applyListQuery(params: URLSearchParams, query: FlowListQuery): void {
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== "" && key !== "limit" && key !== "cursor") params.set(key, String(value));
  }
}

export async function listFlows(
  query: FlowListQuery & { cursor?: string; limit?: number } = {},
): Promise<FlowList> {
  const params = new URLSearchParams();
  applyListQuery(params, query);
  if (query.cursor) {
    params.set("cursor", query.cursor);
  }
  params.set("limit", String(query.limit ?? LIST_PAGE_LIMIT));
  return readJSON<FlowList>(await apiFetch(`/v1/flows?${params.toString()}`));
}

export async function listAllFlows(query: FlowListQuery = {}): Promise<FlowList> {
  const items: Flow[] = [];
  let cursor: string | undefined;
  let generation = 0;
  let revision = "";
  const seen = new Set<string>();
  for (;;) {
    const next = { ...query, limit: LIST_PAGE_LIMIT, ...(cursor ? { cursor } : {}) };
    const chunk = await listFlows(next);
    items.push(...chunk.items);
    generation = chunk.storeGeneration;
    revision = chunk.revision;
    if (!chunk.nextCursor) {
      return { revision, storeGeneration: generation, items, nextCursor: null };
    }
    if (seen.has(chunk.nextCursor)) throw new Error("Flow pagination cursor repeated; refresh the list.");
    seen.add(chunk.nextCursor);
    cursor = chunk.nextCursor;
  }
}

export async function getFlow(id: string): Promise<Flow> {
  return readJSON<Flow>(await apiFetch(`/v1/flows/${encodeURIComponent(id)}`));
}

export function requestBodyURL(id: string): string {
  return `/v1/flows/${encodeURIComponent(id)}/request`;
}

export function responseBodyURL(id: string): string {
  return `/v1/flows/${encodeURIComponent(id)}/response`;
}

export type FlowBodySide = "request" | "response";

export function flowBodyFilename(id: string, side: FlowBodySide): string {
  return `flow-${id}-${side}.bin`;
}

// Fetch via the cookie session and trigger a blob download so a click
// cannot become a top-level navigation to captured HTML.
export async function downloadFlowBody(id: string, side: FlowBodySide): Promise<void> {
  const path = side === "request" ? requestBodyURL(id) : responseBodyURL(id);
  const resp = await apiFetch(path, { headers: { Accept: "application/octet-stream" } });
  if (!resp.ok) {
    const text = await resp.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      parsed = undefined;
    }
    throw new APIError(problemFrom(resp.status, resp.statusText, parsed));
  }
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = flowBodyFilename(id, side);
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

export const CA_DOWNLOAD_URL = "/v1/ca";

export async function deleteFlow(id: string, expectedStoreGeneration?: number): Promise<void> {
  const resp = await apiFetch(`/v1/flows/${encodeURIComponent(id)}${expectedStoreGeneration === undefined ? "" : `?expectedStoreGeneration=${expectedStoreGeneration}`}`, { method: "DELETE" });
  if (resp.status !== 204) {
    await readJSON<unknown>(resp);
  }
}

export async function clearFlows(expectedStoreGeneration?: number): Promise<{ deleted: number }> {
  return readJSON<{ deleted: number }>(await apiFetch(`/v1/flows${expectedStoreGeneration === undefined ? "" : `?expectedStoreGeneration=${expectedStoreGeneration}`}`, { method: "DELETE" }));
}

export async function getStatus(): Promise<Status> {
  return readJSON<Status>(await apiFetch("/v1/status"));
}

export async function getFeatures(): Promise<FeatureList> {
  return readJSON<FeatureList>(await apiFetch("/v1/features"));
}

export async function getState(): Promise<StateView> {
  return readJSON<StateView>(await apiFetch("/v1/state"));
}

export async function applyChanges(body: ChangeSet): Promise<ApplyResult> {
  return readJSON<ApplyResult>(
    await apiFetch("/v1/changes:apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
}

export async function listAudit(): Promise<AuditList> {
  return readJSON<AuditList>(await apiFetch("/v1/audit"));
}

export async function resetState(reason: string): Promise<unknown> {
  return readJSON<unknown>(
    await apiFetch("/v1/state:reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    }),
  );
}

export async function resumeFlow(id: string, patch: { headers?: import("./types").Header[]; body?: string } = {}): Promise<void> {
  await readJSON<unknown>(await apiFetch(`/v1/flows/${encodeURIComponent(id)}:resume`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(patch),
  }));
}
export async function dropFlow(id: string): Promise<void> {
  await readJSON<unknown>(await apiFetch(`/v1/flows/${encodeURIComponent(id)}:drop`, { method: "POST" }));
}
export async function replayFlow(id: string): Promise<Flow> {
  return readJSON<Flow>(await apiFetch(`/v1/flows/${encodeURIComponent(id)}:replay`, { method: "POST" }));
}
export async function waitFlow(filter: import("./types").WaitFilter, timeout: string, signal?: AbortSignal): Promise<Flow> {
  return readJSON<Flow>(await apiFetch("/v1/flows:wait", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ filter, timeout }), ...(signal ? { signal } : {}),
  }));
}
