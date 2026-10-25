import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { isEnvFile } from "../floor/floor.paths.ts";

export type KnownSecret = { name: string; value: string };

/**
 * why a name filter even on `.env`: those files also hold `PORT=3000` and `NODE_ENV=development`, and masking
 * every `development` in every output would be the false positive that gets the rail switched off.
 */
const SENSITIVE_NAME = /(PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH)/i;

// hazard: `PWD` and `OLDPWD` are the shell's working directory, not a password — matching them would mask every
// path the agent prints.
const NOT_SECRETS = new Set(["PWD", "OLDPWD"]);

/**
 * invariant: shorter values are not masked. `dev`, `true`, `admin` appear in ordinary output far more often than as
 * a credential, and a five-character password is not one the mask could meaningfully protect anyway.
 */
export const KNOWN_VALUE_MIN_LENGTH = 6;

// why: a connection string carries its password inside the URL, under a key with no sensitive word in its name.
const URL_USERINFO = /[a-z][a-z0-9+.-]*:\/\/[^:/@\s]+:([^@\s]+)@/gi;

// hazard: a sensitive word also names what points at a secret — `SSH_AUTH_SOCK`, `GOOGLE_APPLICATION_CREDENTIALS`,
// `TOKEN_URL`. Their values are paths and addresses, and masking those would hide where things are, not what they hold.
const POINTER_SUFFIX =
  /_(SOCK|FILE|PATH|DIR|HOME|URL|URI|HOST|PORT|USER|USERNAME|METHOD|TYPE|MODE|ENDPOINT)$/i;

// why: a value that is itself a path is a pointer to a secret, whatever its name says.
const PATH_VALUE = /^(\/|~\/|[A-Za-z]:\\)/;

function isSensitiveName(name: string): boolean {
  return !NOT_SECRETS.has(name) && !POINTER_SUFFIX.test(name) && SENSITIVE_NAME.test(name);
}

function unquote(raw: string): string {
  const value = raw.trim();
  const quoted = /^(["'])(.*)\1$/.exec(value);
  if (quoted) {
    return quoted[2] ?? "";
  }
  // why: an unquoted dotenv value ends at an inline comment, which is how `KEY=value # note` is read by the loaders.
  return value.replace(/\s+#.*$/, "");
}

function parseDotenv(text: string): KnownSecret[] {
  const entries: KnownSecret[] = [];
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$/.exec(line);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      entries.push({ name: match[1], value: unquote(match[2]) });
    }
  }
  return entries;
}

function fromEntries(entries: readonly KnownSecret[]): KnownSecret[] {
  const found: KnownSecret[] = [];
  for (const { name, value } of entries) {
    if (isSensitiveName(name) && !PATH_VALUE.test(value)) {
      found.push({ name, value });
    }
    for (const match of value.matchAll(URL_USERINFO)) {
      if (match[1] !== undefined) {
        found.push({ name, value: decodeURIComponentSafe(match[1]) });
      }
    }
  }
  return found;
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function envFileEntries(projectDir: string): KnownSecret[] {
  let names: string[];
  try {
    names = readdirSync(projectDir);
  } catch {
    return [];
  }
  const entries: KnownSecret[] = [];
  for (const name of names.filter(isEnvFile)) {
    try {
      entries.push(...parseDotenv(readFileSync(join(projectDir, name), "utf8")));
    } catch {}
  }
  return entries;
}

/**
 * The secret values this hook can know for certain: sensitive-named variables in its own environment — which the
 * host passes down, so a key the editor was launched with is among them — and in the project's `.env` files.
 *
 * invariant: read by the hook process, never shown to the model, and never persisted; only the hash of a value
 * that was actually masked reaches disk, through `placeholderFor`.
 */
export function loadKnownSecrets(projectDir: string, env: NodeJS.ProcessEnv = process.env): KnownSecret[] {
  const fromEnv = Object.entries(env).flatMap(([name, value]) =>
    typeof value === "string" ? [{ name, value }] : [],
  );
  const seen = new Set<string>();
  const known: KnownSecret[] = [];
  for (const secret of [...fromEntries(fromEnv), ...fromEntries(envFileEntries(projectDir))]) {
    if (secret.value.length < KNOWN_VALUE_MIN_LENGTH || seen.has(secret.value)) {
      continue;
    }
    seen.add(secret.value);
    known.push(secret);
  }
  return known;
}
