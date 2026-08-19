export const FORBIDDEN_CONTROL_LABELS = [
  "Fuzzer",
  "Repeater",
  "Exploit",
  "SSL-strip",
  "Relay",
  "Payload",
  "Scanner",
] as const;

export type NavItem = { to: string; label: string };

export function navItems(canAudit: boolean, canReset: boolean): NavItem[] {
  const items: NavItem[] = [
    { to: "/", label: "Flows" },
    { to: "/status", label: "Status" },
  ];
  if (canAudit) {
    items.push({ to: "/audit", label: "Audit" });
  }
  if (canReset) {
    items.push({ to: "/reset", label: "Reset" });
  }
  return items;
}

export function containsForbiddenControl(labels: readonly string[]): boolean {
  const set = new Set(labels.map((l) => l.toLowerCase()));
  return FORBIDDEN_CONTROL_LABELS.some((name) => set.has(name.toLowerCase()));
}

export const RESET_PHRASE = "RESET";

export function canSubmitReset(phrase: string, confirmed: boolean, allowed: boolean): boolean {
  return allowed && confirmed && phrase.trim() === RESET_PHRASE;
}
