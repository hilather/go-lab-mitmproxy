/**
 * Shared headless-Chromium harness for the focus checks.
 * Serves any file under harness-dist (`/` is 404). Each script checks its own page.
 */
import { createServer } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { extname, join, sep } from "node:path";
import { chromium } from "playwright-core";

const mime = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
};

export function serve(root) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const path = (req.url || "/").split("?")[0];
      if (path === "/") {
        res.writeHead(404);
        res.end("not found");
        return;
      }
      const file = join(root, path.replace(/^\//, ""));
      if ((file !== root && !file.startsWith(root + sep)) || !existsSync(file)) {
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

export function findChromium() {
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

export async function launch() {
  // Short TMPDIR: long worktree TMPDIR paths make Chromium fatal on SingletonSocket.
  if ((process.env.TMPDIR || "").length > 40) process.env.TMPDIR = "/tmp";
  return chromium.launch({
    executablePath: findChromium(),
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
}
