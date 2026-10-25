import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { projectStateDir } from "../paths.ts";
import { ensureStateIgnored } from "../state-dir.ts";

// hazard: the state — the audit included — was committable in every repository but this one.
test("the state directory ignores itself, so git add . leaves it out of a repository that never listed it", () => {
  const root = mkdtempSync(join(tmpdir(), "tlc-state-dir-"));
  try {
    execFileSync("git", ["init", "-q"], { cwd: root });
    ensureStateIgnored(root);
    writeFileSync(join(projectStateDir(root), "audit.jsonl"), "{}\n");
    assert.equal(readFileSync(join(projectStateDir(root), ".gitignore"), "utf8"), "*\n");
    const untracked = execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], {
      cwd: root,
      encoding: "utf8",
    });
    assert.equal(untracked, "");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an existing marker is left as the operator wrote it", () => {
  const root = mkdtempSync(join(tmpdir(), "tlc-state-dir-"));
  try {
    ensureStateIgnored(root);
    writeFileSync(join(projectStateDir(root), ".gitignore"), "*\n!keep.json\n");
    ensureStateIgnored(root);
    assert.equal(readFileSync(join(projectStateDir(root), ".gitignore"), "utf8"), "*\n!keep.json\n");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
