import { isSecretPath, resolveTarget } from "./floor.paths.ts";
import { type ShellSegment, type ShellWord, tokenizeShell } from "./floor.tokenize.ts";
import { verbOf } from "./floor.verb.ts";

/**
 * hazard: the list used to hold `cat` and eight of its kin, so `sed -n p .env`, `awk 1 .env` and `grep -n KEY .env`
 * printed the same credential `cat .env` was refused for — measured on a live session, where only the agent's own
 * restraint kept the file out of the transcript.
 */
const CONTENT_VERBS = new Set([
  "ack",
  "ag",
  "awk",
  "base64",
  "bat",
  "batcat",
  "cat",
  "cmp",
  "column",
  "comm",
  "cut",
  "diff",
  "egrep",
  "fgrep",
  "fold",
  "gawk",
  "grep",
  "head",
  "hexdump",
  "iconv",
  "jq",
  "less",
  "more",
  "nl",
  "od",
  "paste",
  "perl",
  "rev",
  "rg",
  "sed",
  "sort",
  "strings",
  "tac",
  "tail",
  "uniq",
  "xxd",
  "yq",
]);

/** why: these take their first operand as a pattern, so `grep -rn credentials src` searches for a word. */
const SEARCH_VERBS = new Set(["ack", "ag", "egrep", "fgrep", "grep", "rg"]);
const PATTERN_FLAGS = new Set(["-e", "--regexp", "-f", "--file"]);

/** why: these run inline code, where a secret path is a string literal inside the program, not an operand. */
const INLINE_CODE_VERBS = new Set([
  "awk",
  "bun",
  "deno",
  "gawk",
  "node",
  "perl",
  "php",
  "python",
  "python3",
  "ruby",
]);
const SHELLS = new Set(["ash", "bash", "dash", "fish", "ksh", "sh", "zsh"]);

/** why: `git add .env` names the file; these subcommands print what is in it. */
const GIT_CONTENT_SUBCOMMANDS = new Set(["annotate", "blame", "cat-file", "diff", "grep", "show"]);
const GIT_PATCH_FLAGS = new Set(["-p", "-u", "--patch"]);

/** why: a copy under an ordinary name is a credential this rule no longer recognises by name. */
const COPY_VERBS = new Set(["cp", "ln", "mv", "rsync"]);

const PATH_PIECE = /[A-Za-z0-9_.~/@+-]+/g;
const SUBSTITUTION = /\$\(([^)]*)\)|`([^`]*)`/g;

export type SecretRead = { verb: string; path: string };

// invariant: a bare word is a path only when it is written like one. `npm run credentials` names a script, and a
// floor with no switch cannot afford to read every word as a file.
function looksLikePath(text: string): boolean {
  return text.includes("/") || text.startsWith(".") || text.startsWith("~");
}

function secretIn(projectDir: string, text: string): string | null {
  const resolved = resolveTarget(projectDir, text);
  return isSecretPath(resolved) ? resolved : null;
}

function operands(verb: string, args: readonly ShellWord[]): ShellWord[] {
  const out: ShellWord[] = [];
  let skipNext = false;
  let patternGiven = false;
  for (const word of args) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (SEARCH_VERBS.has(verb) && PATTERN_FLAGS.has(word.text)) {
      skipNext = true;
      patternGiven = true;
      continue;
    }
    if (!word.text.startsWith("-") && word.text !== "" && !word.unresolved) {
      out.push(word);
    }
  }
  return SEARCH_VERBS.has(verb) && !patternGiven ? out.slice(1) : out;
}

function secretOperand(projectDir: string, verb: string, args: readonly ShellWord[]): string | null {
  for (const word of operands(verb, args)) {
    const found = secretIn(projectDir, word.text);
    if (found) {
      return found;
    }
  }
  return null;
}

function secretInCode(projectDir: string, args: readonly ShellWord[]): string | null {
  for (const word of args) {
    for (const piece of word.text.match(PATH_PIECE) ?? []) {
      const found = looksLikePath(piece) ? secretIn(projectDir, piece) : null;
      if (found) {
        return found;
      }
    }
  }
  return null;
}

function gitPrintsContent(args: readonly ShellWord[]): boolean {
  const sub = args.find((word) => !word.text.startsWith("-"))?.text;
  if (sub === undefined) {
    return false;
  }
  return (
    GIT_CONTENT_SUBCOMMANDS.has(sub) || (sub === "log" && args.some((word) => GIT_PATCH_FLAGS.has(word.text)))
  );
}

// why: `cp .env.example .env` is how a project is set up, and `cp .env .env.bak` keeps the copy recognisable.
// Only a copy that lands under a name this rule cannot see is refused.
function copiesOutOfSight(projectDir: string, args: readonly ShellWord[]): string | null {
  const paths = operands("", args);
  const destination = paths.at(-1);
  if (paths.length < 2 || !destination || secretIn(projectDir, destination.text)) {
    return null;
  }
  for (const source of paths.slice(0, -1)) {
    const found = secretIn(projectDir, source.text);
    if (found) {
      return found;
    }
  }
  return null;
}

// why: `python3 < .env` and `while read l; do echo "$l"; done < .env` hand the file to a verb whose operands never
// name it, so the redirect is the only place the path appears.
function redirectedSecret(projectDir: string, words: readonly ShellWord[]): string | null {
  for (let index = 0; index < words.length; index += 1) {
    const word = words[index];
    if (!word || word.quotedStart) {
      continue;
    }
    const inline = word.text.startsWith("<") && word.text.length > 1 ? word.text.slice(1) : null;
    const target = word.text === "<" ? words[index + 1]?.text : inline;
    const found = target ? secretIn(projectDir, target) : null;
    if (found) {
      return found;
    }
  }
  return null;
}

function secretBySegmentVerb(projectDir: string, verb: string, args: readonly ShellWord[]): string | null {
  if (INLINE_CODE_VERBS.has(verb) || (SHELLS.has(verb) && args.some((word) => word.text === "-c"))) {
    return secretOperand(projectDir, verb, args) ?? secretInCode(projectDir, args);
  }
  if (CONTENT_VERBS.has(verb)) {
    return secretOperand(projectDir, verb, args);
  }
  if (verb === "git") {
    // why: `git show HEAD:.env` names the file after the revision, inside one word.
    const paths = args
      .slice(1)
      .map((word) => ({ ...word, text: word.text.slice(word.text.indexOf(":") + 1) }));
    return gitPrintsContent(args) ? secretOperand(projectDir, verb, paths) : null;
  }
  if (COPY_VERBS.has(verb)) {
    return copiesOutOfSight(projectDir, args);
  }
  return null;
}

// why: `echo "$(cat .env)"` carries the read inside a word this gate otherwise skips as unresolved.
function secretInSubstitution(projectDir: string, words: readonly ShellWord[]): SecretRead | null {
  for (const word of words) {
    for (const match of word.text.matchAll(SUBSTITUTION)) {
      const inner = match[1] ?? match[2] ?? "";
      const found = findSecretRead(projectDir, tokenizeShell(inner));
      if (found) {
        return found;
      }
    }
  }
  return null;
}

function secretInSegment(projectDir: string, segment: ShellSegment): SecretRead | null {
  const nested = secretInSubstitution(projectDir, segment.words);
  if (nested) {
    return nested;
  }
  const head = verbOf(segment.words);
  if (!head) {
    return null;
  }
  const path =
    secretBySegmentVerb(projectDir, head.verb, head.args) ?? redirectedSecret(projectDir, segment.words);
  return path ? { verb: head.verb, path } : null;
}

/**
 * invariant: lexical, like the rest of the floor. A recursive search over a directory (`grep -rn KEY .`) is not
 * decided here: whether that directory holds a `.env` is a fact about the disk, and the floor never reads it.
 */
export function findSecretRead(projectDir: string, segments: readonly ShellSegment[]): SecretRead | null {
  for (const segment of segments) {
    const found = secretInSegment(projectDir, segment);
    if (found) {
      return found;
    }
  }
  return null;
}

/** why: a glob is a pattern, not a path, so it is tested against names a credential file would have. */
const SECRET_SAMPLES = [
  ".env",
  ".env.local",
  ".env.production",
  "id_rsa",
  "id_ed25519",
  "deploy.pem",
  "credentials",
];

function globToRegExp(glob: string): RegExp {
  let source = "";
  for (const char of glob) {
    if (char === "*") {
      source += ".*";
    } else if (char === "?") {
      source += ".";
    } else if (char === "{") {
      source += "(";
    } else if (char === "}") {
      source += ")";
    } else if (char === ",") {
      source += "|";
    } else {
      source += char.replace(/[.+^$()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${source}$`);
}

export function globSelectsSecret(glob: string): boolean {
  const last = glob.split("/").pop() ?? glob;
  if (last.startsWith("!")) {
    return false;
  }
  const pattern = globToRegExp(last);
  return SECRET_SAMPLES.some((name) => pattern.test(name));
}
