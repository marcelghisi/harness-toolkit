export type SecretMatch = {
  start: number;
  end: number;
  kind: string;
};

// invariant: shaped like the real thing, never the real thing — a signature fixture that could pass for a working
// credential in its own test file would be the exact leak this module exists to catch.
export const SIGNATURES: Record<string, RegExp> = {
  "aws-access-key": /\bAKIA[0-9A-Z]{16}\b/g,
  "github-token": /\bgh[pousr]_[A-Za-z0-9]{36}\b/g,
  "slack-token": /\bxox[baprs]-[0-9A-Za-z-]{10,72}\b/g,
  "stripe-key": /\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b/g,
  "pem-private-key": /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  jwt: /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\b/g,
};

/**
 * hazard: a human-chosen password is low-entropy and has no provider shape, so `db_password=hunter2` and
 * `postgresql://app:hunter2@db/app` passed through unmasked while every provider key beside them was caught —
 * measured on a fixture set built to probe exactly this.
 *
 * invariant: only the value is masked, never the key or the host, so the agent still sees which field held a
 * secret. A bare `key=value` must sit flush against its `=`: `password = readPassword()` is code, not a leak.
 */
const ASSIGNMENT_KEY =
  "[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|auth[_-]?key|private[_-]?key)[A-Za-z0-9_.-]*";
const QUOTED_ASSIGNMENT = new RegExp(
  String.raw`(?<![A-Za-z0-9_])${ASSIGNMENT_KEY}["']?\s*[:=]\s*(["'])(?<value>[^"'\n]+)\1`,
  "gid",
);
const FLUSH_ASSIGNMENT = new RegExp(
  String.raw`(?<![A-Za-z0-9_])${ASSIGNMENT_KEY}=(?<value>[^\s"'&;,]+)`,
  "gid",
);
const URL_CREDENTIAL = /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:(?<value>[^\s@/]+)@/dgi;

// why: `${DATABASE_PASSWORD}`, `[REDACTED]`, `********` and `<removed>` are what a careful log already prints in
// place of a secret. Masking them again would turn a negative control into a false positive.
const PLACEHOLDER = /^(?:\$|<|\[|\*|%|\{|=)|^(?:null|none|undefined|true|false|redacted|changeme|xxx+)$/i;

function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value) || new Set(value).size === 1;
}

const ASSIGNMENT_PATTERNS: [string, RegExp][] = [
  ["password-assignment", QUOTED_ASSIGNMENT],
  ["password-assignment", FLUSH_ASSIGNMENT],
  ["url-credential", URL_CREDENTIAL],
];

function assignmentMatches(text: string, existing: readonly SecretMatch[]): SecretMatch[] {
  const matches: SecretMatch[] = [];
  for (const [kind, pattern] of ASSIGNMENT_PATTERNS) {
    for (const match of text.matchAll(new RegExp(pattern.source, pattern.flags))) {
      const span = match.indices?.groups?.value;
      const value = match.groups?.value;
      if (!span || value === undefined || isPlaceholder(value)) {
        continue;
      }
      const found = { start: span[0], end: span[1], kind };
      if (![...existing, ...matches].some((other) => overlaps(found, other))) {
        matches.push(found);
      }
    }
  }
  return matches;
}

// why: a run of the base64/hex/token alphabet, long enough to be worth an entropy check at all. Excluding `-` keeps
// a dash-separated UUID out of this pattern entirely — each of its five segments is shorter than the minimum length
// below, so it never reaches the entropy test in the first place.
const ENTROPY_TOKEN_PATTERN = /[A-Za-z0-9+/_=]{20,}/g;

/**
 * why these numbers: measured against this module's own fixtures (see `__test__`) — a 40-character git commit SHA
 * scores ~3.8 bits/char (hex alphabet), a hand-picked high-diversity secret-shaped string scores 5.0. 4.5 sits
 * between them, so a hex-alphabet identifier stays out of the false-positive path while a genuinely high-diversity
 * token still crosses it. The 20-character floor keeps a short common token from crossing it by chance alone.
 */
export const ENTROPY_THRESHOLD = 4.5;
export const ENTROPY_MIN_LENGTH = 20;

export function shannonEntropy(text: string): number {
  if (text.length === 0) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const ch of text) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function signatureMatches(text: string): SecretMatch[] {
  const matches: SecretMatch[] = [];
  for (const [kind, pattern] of Object.entries(SIGNATURES)) {
    const regex = new RegExp(pattern.source, pattern.flags);
    for (const match of text.matchAll(regex)) {
      if (match.index === undefined) {
        continue;
      }
      matches.push({ start: match.index, end: match.index + match[0].length, kind });
    }
  }
  return matches;
}

function overlaps(a: { start: number; end: number }, b: { start: number; end: number }): boolean {
  return a.start < b.end && b.start < a.end;
}

// why: a signature match (an AWS key, a JWT segment) is already high-entropy by construction, so scanning it
// again here would report the same secret as two separate spans — checked against `existing` before this runs.
function entropyMatches(text: string, existing: readonly SecretMatch[]): SecretMatch[] {
  const matches: SecretMatch[] = [];
  for (const match of text.matchAll(ENTROPY_TOKEN_PATTERN)) {
    if (match.index === undefined) {
      continue;
    }
    const span = { start: match.index, end: match.index + match[0].length };
    if (existing.some((existingMatch) => overlaps(span, existingMatch))) {
      continue;
    }
    if (span.end - span.start < ENTROPY_MIN_LENGTH) {
      continue;
    }
    if (shannonEntropy(match[0]) > ENTROPY_THRESHOLD) {
      matches.push({ ...span, kind: "entropy" });
    }
  }
  return matches;
}

// invariant: pure — no I/O, no network call, no subprocess. Every input is a string already in memory.
export function scanForSecrets(text: string | undefined): SecretMatch[] {
  if (!text) {
    return [];
  }
  const signature = signatureMatches(text);
  const assignment = assignmentMatches(text, signature);
  const entropy = entropyMatches(text, [...signature, ...assignment]);
  return [...signature, ...assignment, ...entropy].sort((a, b) => a.start - b.start);
}
