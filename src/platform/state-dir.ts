import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { projectStateDir } from "./paths.ts";

/**
 * hazard: the harness writes its state — the audit included — into every repository it runs in, and only this
 * repository's own `.gitignore` listed it. On any other project a `git add .` would commit it.
 *
 * invariant: the directory ignores itself, so no operator's `.gitignore` has to be edited for it to stay out of git.
 */
export function ensureStateIgnored(root: string): void {
  const marker = join(projectStateDir(root), ".gitignore");
  try {
    if (existsSync(marker)) {
      return;
    }
    mkdirSync(projectStateDir(root), { recursive: true });
    writeFileSync(marker, "*\n");
  } catch {}
}
