import { apiFetch, readJSON } from "./client";
export type ConfigurationOperation = {
  op: string;
  [key: string]: unknown;
};
export type ReviewedChange = {
  expectedRevision: string;
  idempotencyKey: string;
  reason: string;
  force: boolean;
  operations: ConfigurationOperation[];
};
export type ConfigurationPlan = {
  previousRevision: string;
  candidateRevision: string;
  runtimeRevision?: string;
  generation?: number;
  applied?: boolean;
  drifted: boolean;
  diff: {
    path: string;
    op: string;
    before?: unknown;
    after?: unknown;
  }[];
  warnings?: {
    code: string;
    message: string;
  }[];
  operations?: ConfigurationOperation[];
};
export type ConfigurationExport = {
  format: string;
  revision: string;
  bootstrapRevision: string;
  drifted: boolean;
  body: Record<string, unknown>;
  humanDiff?: string;
};
async function post<T>(path: string, body: unknown): Promise<T> {
  return readJSON<T>(
    await apiFetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
}
export function validateConfiguration(input: {
  state?: unknown;
  operations?: ConfigurationOperation[];
}): Promise<ConfigurationPlan> {
  return post("/v1/state:validate", input);
}
export function planConfiguration(
  input: ReviewedChange,
): Promise<ConfigurationPlan> {
  return post("/v1/changes:plan", input);
}
export function applyConfiguration(
  input: ReviewedChange,
): Promise<ConfigurationPlan> {
  return post("/v1/changes:apply", input);
}
export async function exportConfigurationJSON(): Promise<ConfigurationExport> {
  return readJSON<ConfigurationExport>(
    await apiFetch("/v1/state:export?format=json"),
  );
}
export async function exportConfigurationYAMLDocument(): Promise<{
  body: string;
  revision: string;
}> {
  const response = await apiFetch("/v1/state:export?format=yaml", {
    headers: { Accept: "application/yaml" },
  });
  if (!response.ok) await readJSON<never>(response);
  return {
    body: await response.text(),
    revision: response.headers.get("X-LabMITM-Revision") ?? "",
  };
}
export async function exportConfigurationYAML(): Promise<string> {
  return (await exportConfigurationYAMLDocument()).body;
}
export function configurationKey(): string {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
