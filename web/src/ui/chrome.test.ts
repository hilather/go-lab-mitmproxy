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

  it("keeps the 56px masthead, an unclipped Sign out, and no blanket panel wrapping", () => {
    const css = read("styles.css");
    const app = read("App.tsx");
    expect(css).toMatch(/\.topbar\s*\{[^}]*height:\s*56px/);
    expect(css).toMatch(/\.topbar\s*\{[^}]*min-height:\s*56px/);
    expect(css).toMatch(/\.topbar-chips\s*\{[^}]*flex-wrap:\s*nowrap/);
    expect(css).toMatch(/\.topbar-chips \.chip\s*\{[^}]*white-space:\s*nowrap/);
    expect(css).not.toMatch(/\.page\s+\.panel\s*\{[^}]*overflow-wrap:\s*anywhere/);
    expect(css).toMatch(/\.wrap-anywhere\s*\{[^}]*overflow-wrap:\s*anywhere/);
    const chips = app.slice(app.indexOf('className="topbar-chips"'));
    const chipsBlock = chips.slice(0, chips.indexOf("</div>"));
    expect(chipsBlock).not.toMatch(/Sign out/);
    expect(app).toMatch(/topbar-signout/);
  });

  it("uses one danger text colour", () => {
    const css = read("styles.css");
    expect(css).toMatch(/--danger-text:\s*#e38a8a/);
    expect(css).toMatch(/--err-fg:\s*#e38a8a/);
    expect(css).not.toContain("#e8b4b4");
    expect(css).not.toContain("#c47a7a");
  });

  it("has no window.confirm left in product code", () => {
    for (const rel of ["pages/FlowsWorkspace.tsx", "pages/FlowActions.tsx", "pages/FlowInspector.tsx", "pages/StatusPage.tsx", "pages/ConfigurationPage.tsx"]) {
      expect(read(rel)).not.toMatch(/window\.confirm\(/);
    }
  });

  it("bounds the filter popover above the footer with internal scroll", () => {
    const css = read("styles.css");
    expect(css).toMatch(/\.popover\s*\{[^}]*max-height:[^}]*overflow:\s*auto/);
  });

  it("fills white-text danger buttons with a colour that meets 4.5:1", () => {
    const css = read("styles.css");
    const fill = /--danger-fill:\s*(#[0-9a-f]{6})/i.exec(css)?.[1];
    expect(fill).toBeDefined();
    const rule = /button\.btn-danger-fill,\s*button\[type="submit"\]\.btn-danger-fill\s*\{([^}]*)\}/.exec(css)?.[1] ?? "";
    expect(rule).toMatch(/background:\s*var\(--danger-fill\)/);
    expect(rule).toMatch(/color:\s*#fff/);
    const lum = (hex: string) => {
      const [r, g, b] = [1, 3, 5].map((i) => {
        const c = parseInt(hex.slice(i, i + 2), 16) / 255;
        return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
    };
    const ratio = (a: string, b: string) => {
      const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
      return (hi! + 0.05) / (lo! + 0.05);
    };
    expect(ratio("#ffffff", fill!)).toBeGreaterThanOrEqual(4.5);
    // Still reads as a danger control (non-text contrast >= 3:1) on every surface it sits on.
    for (const token of ["--bg", "--elev", "--panel"]) {
      const surface = new RegExp(`${token}:\\s*(#[0-9a-f]{6})`, "i").exec(css)?.[1];
      expect(surface, token).toBeDefined();
      expect(ratio(fill!, surface!), token).toBeGreaterThanOrEqual(3);
    }
  });

  it("has a narrow-viewport block that stacks the shell and the flows workspace", () => {
    const css = read("styles.css");
    const start = css.indexOf("@media (max-width: 720px)");
    expect(start).toBeGreaterThan(-1);
    const block = css.slice(start);
    expect(block).toMatch(/\.app\s*\{[^}]*grid-template-columns:\s*minmax\(0, 1fr\)/);
    // The rail row is only added where a rail exists; the login shell keeps topbar + main.
    expect(block).toMatch(/\.app:has\(\.sidenav\)\s*\{[^}]*"sidenav"/);
    expect(block).not.toMatch(/(^|[\s,}])\.app\s*\{[^}]*grid-template-rows/);
    expect(block).toMatch(/\.workspace-footer\s*\{[^}]*grid-row:\s*3/);
    expect(block).toMatch(/\.panel:has\(table\.data\)\s*\{[^}]*overflow-x:\s*auto/);
    expect(block).toMatch(/\.card-h\s*\{[^}]*flex-wrap:\s*wrap/);
    expect(block).toMatch(/\.split,\s*\.config-grid\s*\{[^}]*grid-template-columns:\s*minmax\(0, 1fr\)/);
    expect(block).toMatch(/\.sidenav\s*\{[^}]*flex-direction:\s*row/);
    expect(block).toMatch(/\.workspace\s*\{[^}]*grid-template-columns:\s*minmax\(0, 1fr\)/);
  });

  it("declares an inline icon so browsers do not request /favicon.ico", () => {
    expect(read("../index.html")).toMatch(/<link rel="icon" href="data:," \/>/);
  });
});
