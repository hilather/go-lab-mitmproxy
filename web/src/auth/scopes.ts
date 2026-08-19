export const SCOPE_READ = "mitm.read";
export const SCOPE_WRITE = "mitm.write";
export const SCOPE_ADMIN = "mitm.admin";
export const SCOPE_AUDIT = "mitm.audit.read";

export function hasScope(scopes: readonly string[], need: string): boolean {
  return scopes.includes(SCOPE_ADMIN) || scopes.includes(need);
}

export function formatBytes(n: number): string {
  if (n < 1024) {
    return `${n} B`;
  }
  if (n < 1024 * 1024) {
    return `${(n / 1024).toFixed(1)} KiB`;
  }
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}
