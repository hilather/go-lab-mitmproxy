import { describe, expect, it } from "vitest";
import { localDateTime, localTime } from "./time";

describe("local time rendering", () => {
  it("renders nanosecond RFC3339 values in local time", () => {
    const iso = "2026-10-03T21:47:35.123456789Z";
    const d = new Date("2026-10-03T21:47:35.123Z");
    const hh = String(d.getHours()).padStart(2, "0");
    expect(localTime(iso)).toBe(`${hh}:47:35`);
    expect(localDateTime(iso)).toMatch(new RegExp(`^\\d{4}-\\d{2}-\\d{2} ${hh}:47:35\\.123$`));
  });

  it("returns unparsable values unchanged", () => {
    expect(localTime("not a time")).toBe("not a time");
    expect(localDateTime(undefined)).toBe("");
  });
});
