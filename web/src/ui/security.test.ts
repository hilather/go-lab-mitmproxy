import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const srcRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) {
      out.push(...walk(p));
      continue;
    }
    if (dir.split(sep).includes("test")) {
      continue;
    }
    if (/\.(ts|tsx)$/.test(ent.name) && !ent.name.endsWith(".test.ts") && !ent.name.endsWith(".test.tsx")) {
      out.push(p);
    }
  }
  return out;
}

describe("XSS and secret handling", () => {
  it("never assigns innerHTML, stores tokens, or ships attack-tool UX", () => {
    const files = walk(srcRoot);
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      expect(text, file).not.toMatch(/dangerouslySetInnerHTML/);
      expect(text, file).not.toMatch(/\.innerHTML\s*=/);
      if (!file.endsWith(`${sep}storage.ts`)) {
        expect(text, file).not.toMatch(/localStorage|sessionStorage|indexedDB/i);
      }
      expect(text, file).not.toMatch(/srcdoc=/);
      expect(text, file).not.toMatch(/allow-scripts|allow-same-origin|allow-popups-to-escape-sandbox/);
      if (!file.endsWith(`${sep}forbidden.ts`)) {
        expect(text, file).not.toMatch(/\b(Fuzzer|Repeater|Exploit|SSL-strip|Relay|Payload generator)\b/);
      }
    }
  });

  it("flow body downloads are attachments, not document navigations", () => {
    const page = readFileSync(join(srcRoot, "pages/FlowInspector.tsx"), "utf8");
    expect(page).toMatch(/download=\{flowBodyFilename/);
    expect(page).toMatch(/ev\.preventDefault\(\)/);
    expect(page).toMatch(/downloadFlowBody/);
    expect(page).not.toMatch(/<a href=\{responseBodyURL\([^)]+\)\}>/);
  });

  it("login is bearer-only", () => {
    const page = readFileSync(join(srcRoot, "pages/LoginPage.tsx"), "utf8");
    expect(page).toMatch(/API bearer token/);
    expect(page).not.toMatch(/Username and password/);
    expect(page).not.toMatch(/basicAuthorization/);
  });
});
