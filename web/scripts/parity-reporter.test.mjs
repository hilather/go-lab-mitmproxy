import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import ParityReporter from "./parity-reporter.mjs";

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "labmitm-parity-reporter-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(
    join(root, "parity.json"),
    JSON.stringify({
      capabilities: {
        "flows.get": {
          evidence: [{ file: "src/flow.test.tsx", test: "Flow reads detail" }],
        },
      },
      operations: {
        replaceTLS: {
          evidence: [
            { file: "src/settings.test.tsx", test: "Settings applies TLS" },
          ],
        },
      },
    }),
  );
  const reporter = new ParityReporter();
  reporter.onInit({ config: { root } });
  const result = (file, name, state = "passed") =>
    reporter.onTestCaseResult({
      module: { moduleId: resolve(root, file) },
      fullName: name,
      result: () => ({ state }),
    });
  return { reporter, result };
}

test("accepts passing evidence for every capability and operation", (t) => {
  const { reporter, result } = fixture(t);
  result("src/flow.test.tsx", "Flow reads detail");
  result("src/settings.test.tsx", "Settings applies TLS");
  assert.doesNotThrow(() => reporter.onTestRunEnd());
});

for (const state of ["skipped", "pending", "failed"]) {
  test(`rejects ${state} behavioral evidence`, (t) => {
    const { reporter, result } = fixture(t);
    result("src/flow.test.tsx", "Flow reads detail", state);
    result("src/settings.test.tsx", "Settings applies TLS");
    assert.throws(
      () => reporter.onTestRunEnd(),
      /flows.get: src\/flow.test.tsx > Flow reads detail/,
    );
  });
}

test("rejects missing and renamed named tests", (t) => {
  const { reporter, result } = fixture(t);
  result("src/flow.test.tsx", "Flow renamed detail");
  assert.throws(() => reporter.onTestRunEnd(), /flows.get:/);
  assert.throws(() => reporter.onTestRunEnd(), /replaceTLS:/);
});

test("rejects passing tests from the wrong file", (t) => {
  const { reporter, result } = fixture(t);
  result("src/other.test.tsx", "Flow reads detail");
  result("src/settings.test.tsx", "Settings applies TLS");
  assert.throws(() => reporter.onTestRunEnd(), /flows.get:/);
});

test("rejects missing or malformed manifests", (t) => {
  const { reporter } = fixture(t);
  writeFileSync(join(reporter.root, "parity.json"), "invalid JSON");
  assert.throws(() => reporter.onTestRunEnd(), SyntaxError);
  rmSync(join(reporter.root, "parity.json"));
  assert.throws(() => reporter.onTestRunEnd(), /ENOENT/);
});
