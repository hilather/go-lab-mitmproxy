import { readFileSync } from "node:fs";
import { relative, resolve } from "node:path";

// A manifest entry only counts when the named behavioral test actually ran and
// passed. Skipped/todo/missing/renamed tests fail closed, even in a green suite.
export default class ParityReporter {
  passed = new Set();
  onInit(ctx) {
    this.root = ctx.config.root;
  }
  onTestCaseResult(test) {
    if (test.result().state === "passed") {
      this.passed.add(
        `${relative(this.root, test.module.moduleId)}\n${test.fullName}`,
      );
    }
  }
  onTestRunEnd() {
    const manifest = JSON.parse(
      readFileSync(resolve(this.root, "parity.json"), "utf8"),
    );
    const missing = [];
    for (const [name, row] of Object.entries({
      ...manifest.capabilities,
      ...manifest.operations,
    })) {
      for (const item of row.evidence) {
        if (!this.passed.has(`${item.file}\n${item.test}`)) {
          missing.push(`${name}: ${item.file} > ${item.test}`);
        }
      }
    }
    if (missing.length)
      throw new Error(
        `Frontend parity lacks passing behavioral evidence:\n${missing.join("\n")}`,
      );
  }
}
