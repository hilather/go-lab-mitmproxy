import { describe, expect, it } from "vitest";
import { canSubmitReset, containsForbiddenControl, navItems } from "./forbidden";

describe("operator nav", () => {
  it("has no fuzzer, repeater, exploit, or SSL-strip controls", () => {
    const labels = navItems(true, true).map((i) => i.label);
    expect(containsForbiddenControl(labels)).toBe(false);
    expect(labels).toEqual(["Flows", "Status", "Audit", "Reset"]);
    expect(navItems(false, false).map((i) => i.label)).toEqual(["Flows", "Status"]);
  });

  it("gates reset on the exact phrase and confirmation", () => {
    expect(canSubmitReset("RESET", true, true)).toBe(true);
    expect(canSubmitReset("reset", true, true)).toBe(false);
    expect(canSubmitReset("RESET", false, true)).toBe(false);
    expect(canSubmitReset("RESET", true, false)).toBe(false);
  });
});
