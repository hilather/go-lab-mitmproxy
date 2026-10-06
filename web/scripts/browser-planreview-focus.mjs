#!/usr/bin/env node
/**
 * Headless Chromium check: Status plan review must restore focus to #app-main.
 * Chrome moves focus to <body> when the busy switch disables; jsdom does not.
 * Each case reloads the page. A failure is reported and the next case still runs.
 */
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { launch, serve } from "./browser-harness.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "harness-dist");
const pagePath = join(root, "harness", "planreview-focus.html");
if (!existsSync(pagePath)) {
  console.error("missing harness-dist; run: vite build --config vite.harness.config.ts");
  process.exit(2);
}

async function activeElement(page) {
  return page.evaluate(() => {
    const el = document.activeElement;
    return {
      tagName: el?.tagName ?? null,
      id: el?.id ?? "",
      ariaLabel: el?.getAttribute?.("aria-label") ?? null,
    };
  });
}

async function runCase(page, port, name) {
  await page.goto(`http://127.0.0.1:${port}/harness/planreview-focus.html`, { waitUntil: "networkidle" });
  if (name === "submit") {
    // Default opener: applyOp reads document.activeElement at call entry. A real click on the
    // admission submit (populated from sampleState) is that element, not the feature switch.
    const applyAdmission = page.getByRole("button", { name: "Apply admission" });
    await applyAdmission.waitFor();
    await page.waitForFunction(() => {
      const button = Array.from(document.querySelectorAll("button")).find(
        (el) => el.textContent?.trim() === "Apply admission",
      );
      return button instanceof HTMLButtonElement && !button.disabled;
    });
    await applyAdmission.click();
  } else if (name === "escape" || name === "discard" || name === "apply") {
    await page.getByLabel("Toggle rules.enabled").click();
  } else {
    throw new Error(`unknown case ${name}`);
  }
  const dialog = page.getByRole("dialog", { name: "Review planned change" });
  await dialog.waitFor();
  await page.waitForFunction(() => document.activeElement?.closest('[role="dialog"]') != null);
  if (name === "escape" || name === "submit") {
    await page.keyboard.press("Escape");
  } else if (name === "discard") {
    await page.getByRole("button", { name: "Discard plan" }).click();
  } else if (name === "apply") {
    await page.getByRole("button", { name: "Apply reviewed changes" }).click();
  } else {
    throw new Error(`unknown case ${name}`);
  }
  await dialog.waitFor({ state: "detached" });
  await page.waitForFunction(() => document.activeElement?.id === "app-main", null, { timeout: 2000 });
  await page.waitForTimeout(50);
  const id = await page.evaluate(() => document.activeElement?.id);
  if (id !== "app-main") {
    throw new Error(`focus left #app-main, now ${id ?? "null"}`);
  }
  const calls = await page.evaluate(() => window.__applyCalls);
  const expected = name === "apply" ? 1 : 0;
  if (calls !== expected) {
    throw new Error(`__applyCalls ${calls}, expected ${expected}`);
  }
}

const cases = ["escape", "discard", "apply", "submit"];
const { server, port } = await serve(root);
const browser = await launch();
const failures = [];
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  for (const name of cases) {
    try {
      await runCase(page, port, name);
      console.log(`ok ${name}`);
    } catch (err) {
      let snapshot = "unavailable";
      try {
        snapshot = JSON.stringify(await activeElement(page));
      } catch (snapErr) {
        snapshot = `snapshot failed: ${snapErr instanceof Error ? snapErr.message : snapErr}`;
      }
      const message = err instanceof Error ? err.message : String(err);
      console.log(`FAIL ${name}: ${message}`);
      console.log(`activeElement ${snapshot}`);
      failures.push(name);
    }
  }
  if (failures.length > 0) {
    console.log(`browser-planreview-focus: FAIL (${failures.join(", ")})`);
  } else {
    console.log("browser-planreview-focus: PASS");
  }
} finally {
  await browser.close();
  server.close();
}
if (failures.length > 0) process.exit(1);
