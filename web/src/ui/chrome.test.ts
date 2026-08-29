import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const srcRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function read(rel: string): string {
  return readFileSync(join(srcRoot, rel), "utf8");
}

function unadornedButtonRule(css: string): string {
  const matches = [...css.matchAll(/(?:^|})\s*(button)\s*\{([^}]*)\}/g)];
  const rule = matches.find((m) => m[1] === "button");
  if (!rule) {
    throw new Error("unadorned button { } rule not found");
  }
  return rule[2] ?? "";
}

describe("operator chrome lock", () => {
  it("keeps dark lab tokens and IBM Plex, not paper/navy/Segoe", () => {
    const css = read("styles.css");
    for (const token of ["#0b0c0e", "#121317", "#181a1f", "#ecece8", "#6ea8d1", "#c4a35a", "IBM Plex"]) {
      expect(css).toContain(token);
    }
    expect(css).not.toMatch(/Segoe/);
    expect(css).not.toContain("#eef2f4");
    expect(css).not.toContain("#fffdf8");
    expect(css).not.toContain("#16324f");
    expect(css).not.toContain("color-scheme: light");
  });

  it("styles default buttons and .panel on page bodies", () => {
    const css = read("styles.css");
    const button = unadornedButtonRule(css);
    expect(button).toMatch(/background/);
    expect(button).toMatch(/font:\s*inherit/);
    expect(css).toMatch(/\.panel\s*\{[^}]*var\(--panel\)/);
    expect(css).toMatch(/\.panel\s*\{[^}]*var\(--line\)/);
    expect(css).toMatch(/\.panel\s*\{[^}]*border-radius/);
    expect(css).toMatch(/accent-color:\s*var\(--accent\)/);
    expect(css).toMatch(/input:-webkit-autofill/);
    expect(css).toMatch(/code\s*\{[^}]*IBM Plex Mono/);
  });

  it("restyles leftover page bodies, not only the shell", () => {
    const login = read("pages/LoginPage.tsx");
    const status = read("pages/StatusPage.tsx");
    const audit = read("pages/AuditPage.tsx");
    const reset = read("pages/ResetPage.tsx");
    expect(login).toMatch(/className="[^"]*panel/);
    expect(status).toMatch(/className="[^"]*panel/);
    expect(audit).toMatch(/className="[^"]*panel/);
    expect(reset).toMatch(/className="[^"]*panel/);
    expect(status).toMatch(/className="kicker"/);
    expect(audit).toMatch(/className="kicker"/);
    expect(reset).toMatch(/className="kicker"/);
    expect(login).toMatch(/className="kicker"/);
    expect(status).not.toMatch(/tunnel-not-decrypt/);
    expect(audit).not.toMatch(/tunnel-not-decrypt/);
    expect(reset).not.toMatch(/tunnel-not-decrypt/);
    expect(login).not.toMatch(/tunnel-not-decrypt/);
  });
});
