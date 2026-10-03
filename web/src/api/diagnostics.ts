import { apiFetch, readJSON } from "./client";
import type { AuditEvent, AuditList } from "./types";
export type FullAuditEvent = AuditEvent & {
  diff?: {
    path: string;
    op: string;
    before?: unknown;
    after?: unknown;
  }[];
};
export const diagnosticReads = [
  { id: "version.get", title: "Version", path: "/v1/version" },
  { id: "capabilities.get", title: "Capabilities", path: "/v1/capabilities" },
  {
    id: "schema.get",
    title: "Configuration schema",
    path: "/v1/schema/config",
  },
  { id: "health.live", title: "Liveness", path: "/v1/health/live" },
  { id: "health.ready", title: "Readiness", path: "/v1/health/ready" },
  { id: "metrics.get", title: "Metrics", path: "/v1/metrics" },
] as const;
export type DiagnosticRead = (typeof diagnosticReads)[number];
export async function getDiagnostic(read: DiagnosticRead): Promise<unknown> {
  const response = await apiFetch(
    read.path,
    read.id === "metrics.get"
      ? {
          headers: { Accept: "application/openmetrics-text" },
        }
      : {},
  );
  // A failed readiness probe still carries useful status JSON.
  if (read.id.startsWith("health.") && response.status === 503) {
    return {
      httpStatus: response.status,
      ...((await response.json()) as Record<string, unknown>),
    };
  }
  if (read.id === "metrics.get" && response.ok) return response.text();
  return readJSON<unknown>(response);
}
export async function queryAudit(limit?: number): Promise<AuditList> {
  return readJSON<AuditList>(
    await apiFetch(
      limit === undefined
        ? "/v1/audit"
        : `/v1/audit?limit=${encodeURIComponent(limit)}`,
    ),
  );
}
export async function getAudit(id: string): Promise<FullAuditEvent> {
  return readJSON<FullAuditEvent>(
    await apiFetch(`/v1/audit/${encodeURIComponent(id)}`),
  );
}
