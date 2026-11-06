import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

// Test the exact checked-in oracle and kill behavior-changing source mutants.
// This tests MODEL CONSISTENCY only, not a production implementation.
const source = readFileSync(new URL("./check_safety.mjs", import.meta.url), "utf8");
function run(text) {
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", text], {
    encoding: "utf8", timeout: 10000, maxBuffer: 256 * 1024
  });
  assert.equal(child.error, undefined, String(child.error));
  return child;
}
test("unmodified bounded oracle passes with nonzero evidence", () => {
  const result = run(source);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout.trim());
  assert.ok((report.states || report.edges) > 0, "empty state-space evidence");
});
const mutants = [["cache TTL is extended beyond bound","cacheUntil:s.now+1","cacheUntil:s.now+2"],["introspection caches wrong key generation","cacheGen:gen","cacheGen:1"],["revoked or stale key renews grant","if(freshAllowed(s))next.push","if(true)next.push"],["revocation action disappears","if(!s.revoked)next.push","if(false)next.push"],["rotation action disappears","if(s.activeGen===1)next.push","if(false)next.push"],["expiry boundary becomes inclusive","cacheGen===s.presentedGen&&s.now<s.cacheUntil","cacheGen===s.presentedGen&&s.now<=s.cacheUntil"]];
for (const [label, original, replacement] of mutants) {
  test("rejects mutant: " + label, () => {
    assert.equal(source.split(original).length - 1, 1, "mutation anchor drift: " + label);
    const runResult = run(source.replace(original, replacement));
    assert.notEqual(runResult.status, 0, "mutant survived: " + label);
    assert.match(runResult.stderr, /Error|AssertionError/, "mutant had no assertion failure: " + label);
  });
}
