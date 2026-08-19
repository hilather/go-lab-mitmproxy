import { assertNoTokenStorage } from "./storage";
import type { AuditList, Flow, FlowList, FlowListQuery, Problem, SessionCreated, SessionView, Status } from "./types";

export const CSRF_HEADER = "X-LabMITM-CSRF";

export class APIError extends Error {
  readonly problem: Problem;

  constructor(problem: Problem) {
    super(problem.detail || problem.title || "request failed");
    this.name = "APIError";
    this.problem = problem;
  }
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

async function readJSON<T>(resp: Response): Promise<T> {
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
const LIST_MAX_PAGES = 16;

function applyListQuery(params: URLSearchParams, query: FlowListQuery): void {
  if (query.host) {
    params.set("host", query.host);
  }
  if (query.method) {
    params.set("method", query.method);
  }
  if (query.status) {
    params.set("status", query.status);
  }
  if (query.scheme) {
    params.set("scheme", query.scheme);
  }
  if (query.intercepted) {
    params.set("intercepted", query.intercepted);
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
  for (let page = 0; page < LIST_MAX_PAGES; page += 1) {
    const next: FlowListQuery & { cursor?: string; limit: number } = {
      limit: LIST_PAGE_LIMIT,
    };
    if (query.host) {
      next.host = query.host;
    }
    if (query.method) {
      next.method = query.method;
    }
    if (query.status) {
      next.status = query.status;
    }
    if (query.scheme) {
      next.scheme = query.scheme;
    }
    if (query.intercepted) {
      next.intercepted = query.intercepted;
    }
    if (cursor) {
      next.cursor = cursor;
    }
    const chunk = await listFlows(next);
    items.push(...chunk.items);
    generation = chunk.storeGeneration;
    revision = chunk.revision;
    if (!chunk.nextCursor) {
      return { revision, storeGeneration: generation, items, nextCursor: null };
    }
    cursor = chunk.nextCursor;
  }
  return { revision, storeGeneration: generation, items, nextCursor: cursor ?? null };
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

export async function deleteFlow(id: string): Promise<void> {
  const resp = await apiFetch(`/v1/flows/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (resp.status !== 204) {
    await readJSON<unknown>(resp);
  }
}

export async function clearFlows(): Promise<{ deleted: number }> {
  return readJSON<{ deleted: number }>(await apiFetch("/v1/flows", { method: "DELETE" }));
}

export async function getStatus(): Promise<Status> {
  return readJSON<Status>(await apiFetch("/v1/status"));
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
