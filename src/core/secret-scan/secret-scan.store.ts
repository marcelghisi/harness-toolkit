import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { projectStateDir } from "../../platform/paths.ts";

// invariant: keyed by a hash of the matched text, never the raw value — this file is the only durable
// record of a redaction, so it must not become a second copy of the secret it exists to hide.
type SecretRedactionStore = {
  [sessionKey: string]: {
    [textHash: string]: string;
  };
};

function storePath(root: string): string {
  return join(projectStateDir(root), "secret-redaction.json");
}

function readStore(root: string): SecretRedactionStore {
  const path = storePath(root);
  if (!existsSync(path)) {
    return {};
  }
  try {
    return JSON.parse(readFileSync(path, "utf8")) as SecretRedactionStore;
  } catch {
    return {};
  }
}

function writeStore(root: string, store: SecretRedactionStore): void {
  try {
    mkdirSync(projectStateDir(root), { recursive: true });
    writeFileSync(storePath(root), `${JSON.stringify(store, null, 2)}\n`, "utf8");
  } catch {}
}

function hashOf(matchedText: string): string {
  return createHash("sha256").update(matchedText).digest("hex").slice(0, 8);
}

/**
 * The placeholders this session has handed out, and only those.
 *
 * why from the store and not a pattern: a placeholder-shaped string is also a legitimate thing to write — a test
 * fixture, a doc describing the format. Only a placeholder this session produced proves the text came from a masked
 * read rather than from the author.
 */
export function sessionPlaceholders(root: string, sessionKey: string): string[] {
  return Object.values(readStore(root)[sessionKey] ?? {});
}

// invariant: the same matchedText within the same session always resolves to the same placeholder, keyed by a
// hash rather than the raw value.
export function placeholderFor(root: string, sessionKey: string, matchedText: string, kind: string): string {
  const store = readStore(root);
  const session = store[sessionKey] ?? {};
  const hash = hashOf(matchedText);
  const existing = session[hash];
  if (existing !== undefined) {
    return existing;
  }
  const placeholder = `[REDACTED:${kind}:${hash}]`;
  session[hash] = placeholder;
  store[sessionKey] = session;
  writeStore(root, store);
  return placeholder;
}
