import { describe, expect, it } from "vitest";
import { isTextualContentType, looksLikeText, shouldRenderAsText, toHexDump } from "./bodyView";

describe("body view", () => {
  it("treats json xml form and text as textual", () => {
    expect(isTextualContentType("application/json; charset=utf-8")).toBe(true);
    expect(isTextualContentType("application/problem+json")).toBe(true);
    expect(isTextualContentType("text/html")).toBe(true);
    expect(isTextualContentType("application/xml")).toBe(true);
    expect(isTextualContentType("application/x-www-form-urlencoded")).toBe(true);
    expect(isTextualContentType("image/png")).toBe(false);
    expect(isTextualContentType("application/octet-stream")).toBe(false);
  });

  it("renders HTML as escaped text, not as a live document", () => {
    expect(shouldRenderAsText("text/html", "<script>alert(1)</script>")).toBe(true);
    expect(looksLikeText("<html><body>hi</body></html>")).toBe(true);
  });

  it("hex-dumps binary payloads", () => {
    const dump = toHexDump("\x00\x01ABC");
    expect(dump).toMatch(/00 01 41 42 43/);
    expect(dump).toMatch(/\.\.ABC/);
  });
});
