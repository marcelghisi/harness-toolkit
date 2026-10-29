import { createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { projectStateDir, runtimeStateDir } from "../../platform/paths.ts";
import type { PiiMode } from "./pii-scan.packs.ts";
import type { KeepAttribute } from "./pii-scan.template.ts";

export const PII_SALT_FILE = "pii-salt";

/**
 * hazard: a bare hash of an email is reversible — hash a list of known addresses and compare. A per-machine salt the
 * agent cannot read (the floor treats it as a secret) is what keeps a pseudonym from being a lookup key.
 */
function saltOf(): string {
  const path = join(runtimeStateDir(), PII_SALT_FILE);
  try {
    return readFileSync(path, "utf8").trim();
  } catch {}
  const salt = randomBytes(32).toString("hex");
  try {
    mkdirSync(runtimeStateDir(), { recursive: true });
    writeFileSync(path, `${salt}\n`, { mode: 0o600, flag: "wx" });
  } catch {
    // why: another hook may have written it first; theirs is the one every later read will agree on.
    try {
      return readFileSync(path, "utf8").trim();
    } catch {}
  }
  return salt;
}

// why: one person, one token — `Ana@Corp.io` and `ana@corp.io`, or a phone with and without spaces, are the same value.
function canonical(kind: string, value: string): string {
  const trimmed = value.trim();
  if (kind === "email") {
    return trimmed.toLowerCase();
  }
  return /^[\d\s.+()/-]+$/.test(trimmed) ? trimmed.replace(/\D/g, "") : trimmed.toLowerCase();
}

const ONE_DIGIT_CODES = new Set(["1", "7"]);
const TWO_DIGIT_CODES = new Set(
  "20 27 30 31 32 33 34 36 39 40 41 43 44 45 46 47 48 49 51 52 53 54 55 56 57 58 60 61 62 63 64 65 66 81 82 84 86 90 91 92 93 94 95 98".split(
    " ",
  ),
);

function countryCode(value: string): string | null {
  const digits = value.trim().startsWith("+") ? value.replace(/\D/g, "") : "";
  if (digits === "") {
    return null;
  }
  if (ONE_DIGIT_CODES.has(digits.slice(0, 1))) {
    return digits.slice(0, 1);
  }
  return TWO_DIGIT_CODES.has(digits.slice(0, 2)) ? digits.slice(0, 2) : digits.slice(0, 3);
}

function cardBrand(digits: string): string {
  if (digits.startsWith("4")) {
    return "visa";
  }
  if (/^(5[1-5]|2[2-7])/.test(digits)) {
    return "mastercard";
  }
  if (/^3[47]/.test(digits)) {
    return "amex";
  }
  return /^(6011|65|64[4-9])/.test(digits) ? "discover" : "card";
}

// why: the attributes that let analysis go on — a domain, a country, a brand and last four — none of which names a
// person on its own.
function visibleAttribute(kind: string, value: string, keep: ReadonlySet<KeepAttribute>): string {
  if (kind === "email" && keep.has("email-domain")) {
    const at = value.lastIndexOf("@");
    return at === -1
      ? ""
      : `@${value
          .slice(at + 1)
          .trim()
          .toLowerCase()}`;
  }
  if (kind === "phone" && keep.has("phone-country")) {
    const code = countryCode(value);
    return code ? `:+${code}` : "";
  }
  if (kind === "card" && keep.has("card-last4")) {
    const digits = value.replace(/\D/g, "");
    return `:${cardBrand(digits)}…${digits.slice(-4)}`;
  }
  return "";
}

function storePath(root: string): string {
  return join(projectStateDir(root), "pii-pseudonyms.json");
}

function readTokens(root: string): Record<string, string[]> {
  if (!existsSync(storePath(root))) {
    return {};
  }
  try {
    return JSON.parse(readFileSync(storePath(root), "utf8")) as Record<string, string[]>;
  } catch {
    return {};
  }
}

/**
 * invariant: the record holds the tokens a session was handed and nothing else — never a value, never a hash input —
 * so it proves a token came from a masked read without becoming a copy of what was masked.
 */
function rememberToken(root: string, sessionKey: string, token: string): void {
  const store = readTokens(root);
  const tokens = store[sessionKey] ?? [];
  if (tokens.includes(token)) {
    return;
  }
  store[sessionKey] = [...tokens, token];
  try {
    mkdirSync(projectStateDir(root), { recursive: true });
    writeFileSync(storePath(root), `${JSON.stringify(store, null, 2)}\n`, "utf8");
  } catch {}
}

export function sessionPseudonyms(root: string, sessionKey: string): string[] {
  return readTokens(root)[sessionKey] ?? [];
}

export type PseudonymRequest = {
  root: string;
  sessionKey: string;
  value: string;
  kind: string;
  mode: PiiMode;
  keep: ReadonlySet<KeepAttribute>;
};

/**
 * invariant: the same value under the same kind yields the same token in every session on this machine, so rows
 * still join and duplicates still show — and a `mask`-mode kind carries no visible attribute at all.
 */
export function pseudonymFor(request: PseudonymRequest): string {
  const hash = createHmac("sha256", saltOf())
    .update(`${request.kind}:${canonical(request.kind, request.value)}`)
    .digest("hex")
    .slice(0, 8);
  const attribute =
    request.mode === "mask" ? "" : visibleAttribute(request.kind, request.value, request.keep);
  const token = `[PII:${request.kind}:${hash}${attribute}]`;
  rememberToken(request.root, request.sessionKey, token);
  return token;
}
