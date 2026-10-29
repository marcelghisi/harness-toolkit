import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCandidates } from "../pii-cli.ts";

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
