import assert from "node:assert/strict";
import { test } from "node:test";
import { lineDiff, parseCandidates, planApply } from "../pii-cli.ts";

// invariant: the candidate list is the one input an agent writes, so it carries names and nothing that compiles.
test("candidates keep a name, a kind, a mode and evidence, and drop everything else", () => {
  const parsed = parseCandidates(
    JSON.stringify([
      "customerEmail",
      { name: "titular", kind: "name", mode: "mask", evidence: "Conta.java", regex: ".*", extends: ["x"] },
      { name: "nota", mode: "plaintext", kind: "Not A Kind" },
      { name: "" },
      42,
    ]),
  );
  assert.deepEqual(parsed, [
    { name: "customerEmail" },
    { name: "titular", kind: "name", mode: "mask", evidence: "Conta.java" },
    { name: "nota" },
  ]);
  assert.deepEqual(parseCandidates('{"name":"x"}'), []);
});

test("apply refuses a proposal that does not compile, whole, and names why", () => {
  const plan = planApply(
    null,
    JSON.stringify({ extends: ["id:zz"], patterns: [{ kind: "x", regex: "(" }], extra: 1 }),
  );
  assert.equal(plan.ok, false);
  const errors = plan.ok ? [] : plan.errors.join("\n");
  assert.match(String(errors), /unknown key `extra`/);
  assert.match(String(errors), /id:zz/);
  assert.equal(planApply(null, "{not json").ok, false);
  assert.equal(planApply(null, "[]").ok, false);
});

test("apply plans the exact file and a line diff against the current template", () => {
  const current = `${JSON.stringify({ extends: ["global"], fields: ["a"] }, null, 2)}\n`;
  const plan = planApply(current, JSON.stringify({ extends: ["global"], fields: ["a", "b"] }));
  assert.ok(plan.ok);
  if (plan.ok) {
    assert.equal(plan.unchanged, false);
    assert.ok(plan.diff.includes('+     "b"'), plan.diff.join("\n"));
    assert.ok(plan.diff.includes('-     "a"'));
    assert.ok(plan.diff.includes('+     "a",'));
    assert.equal(plan.next, `${JSON.stringify({ extends: ["global"], fields: ["a", "b"] }, null, 2)}\n`);
  }
  const same = planApply(current, current);
  assert.ok(same.ok && same.unchanged);
});

test("the line diff keeps common lines and marks the rest", () => {
  assert.deepEqual(lineDiff(["a", "b", "c"], ["a", "c", "d"]), ["  a", "- b", "  c", "+ d"]);
  assert.deepEqual(lineDiff([], ["x"]), ["+ x"]);
});
