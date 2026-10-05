#!/usr/bin/env node
/**
 * Headless Chromium check: Filters outside-click on non-focusable chrome must
 * leave focus on "Filters & wait" after the full click (not only after mousedown).
 * jsdom does not replay Chrome's post-click blur; this catches that gap.
 */
import { createServer } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { extname, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "harness-dist");
if (!existsSync(join(root, "harness", "filters-focus.html"))) {
  console.error("missing harness-dist; run: vite build --config vite.harness.config.ts");
  process.exit(2);
}

const mime = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
};

function serve() {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      let path = (req.url || "/").split("?")[0];
      if (path === "/") path = "/harness/filters-focus.html";
      const file = join(root, path.replace(/^\//, ""));
      if (!file.startsWith(root) || !existsSync(file)) {
        res.writeHead(404);
        res.end("not found");
        return;
      }
      res.writeHead(200, { "Content-Type": mime[extname(file)] || "application/octet-stream" });
      res.end(readFileSync(file));
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, port });
    });
  });
}

function findChromium() {
  if (process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH) return process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
  for (const c of [
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
  ]) {
    if (existsSync(c)) return c;
  }
  return undefined;
}
const executablePath = findChromium();

async function assertRestore(page, clickSelector, label, { holdMs = 0 } = {}) {
  const trigger = page.getByRole("button", { name: "Filters & wait" });
  await trigger.click();
  await page.getByRole("dialog", { name: "Server filters and wait" }).waitFor();
  const target = page.locator(clickSelector);
  await target.scrollIntoViewIfNeeded();
  const box = await target.boundingBox();
  if (!box) throw new Error(`${label}: no box`);
  const x = box.x + box.width / 2;
  const y = box.y + Math.min(box.height / 2, 8);
  await page.mouse.move(x, y);
  await page.mouse.down();
  if (holdMs > 0) await page.waitForTimeout(holdMs);
  await page.mouse.up();
  await page.waitForFunction(() => {
    const btn = [...document.querySelectorAll("button")].find((b) => b.textContent?.includes("Filters & wait"));
    return btn?.getAttribute("aria-expanded") === "false";
  });
  await page.waitForFunction(() => {
    const btn = [...document.querySelectorAll("button")].find((b) => b.textContent?.includes("Filters & wait"));
    return btn != null && document.activeElement === btn;
  }, null, { timeout: 2000 });
  const active = await page.evaluate(() => document.activeElement?.textContent?.trim() ?? document.activeElement?.tagName);
  if (!String(active).includes("Filters & wait")) {
    throw new Error(`${label}: expected focus on Filters & wait, got ${JSON.stringify(active)}`);
  }
  console.log(`ok ${label}${holdMs ? ` (hold ${holdMs}ms)` : ""}`);
}

const { server, port } = await serve();
// Short TMPDIR: long worktree TMPDIR paths make Chromium fatal on SingletonSocket.
if ((process.env.TMPDIR || "").length > 40) process.env.TMPDIR = "/tmp";
const browser = await chromium.launch({
  executablePath,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  await page.goto(`http://127.0.0.1:${port}/harness/filters-focus.html`, { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "Filters & wait" }).waitFor();

  for (const [sel, label] of [
    ['[data-testid="outside-kicker"]', "kicker"],
    ['[data-testid="outside-h1"]', "h1"],
    ['[data-testid="outside-footer"]', "footer"],
    ['[data-testid="outside-topbar"]', "topbar"],
  ]) {
    await assertRestore(page, sel, label);
  }
  // Slow press: restore must wait for click, not a mousedown timer.
  await assertRestore(page, '[data-testid="outside-kicker"]', "kicker-hold", { holdMs: 150 });

  // Focusable target: outside mousedown on #flow-search must close without stealing focus back.
  const trigger = page.getByRole("button", { name: "Filters & wait" });
  await trigger.click();
  await page.getByRole("dialog", { name: "Server filters and wait" }).waitFor();
  await page.evaluate(() => {
    const input = document.getElementById("flow-search");
    input.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true, view: window }));
    input.focus();
  });
  await page.waitForFunction(() => {
    const btn = [...document.querySelectorAll("button")].find((b) => b.textContent?.includes("Filters & wait"));
    return btn?.getAttribute("aria-expanded") === "false" && document.activeElement?.id === "flow-search";
  }, null, { timeout: 2000 });
  // Allow the macrotask restore window; focus must still be the search input.
  await page.waitForTimeout(50);
  const still = await page.evaluate(() => document.activeElement?.id);
  if (still !== "flow-search") throw new Error(`flow-search lost focus to ${still}`);
  console.log("ok flow-search keeps focus");

  console.log("browser-filters-focus: PASS");
} finally {
  await browser.close();
  server.close();
}
