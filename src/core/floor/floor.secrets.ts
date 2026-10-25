import { isSecretPath, resolveTarget } from "./floor.paths.ts";
import type { ShellWord } from "./floor.tokenize.ts";

/**
 * Every verb that prints the content of a file it is handed, not only `cat` and its kin.
 *
 * hazard: the list held the nine byte-dumpers, so `cat .env` was refused while `grep . .env`, `sed -n p .env` and
 * `awk 1 .env` printed the same file through the same transcript ([/decisions/ad-150.md](/decisions/ad-150.md)).
 *
 * invariant: a verb whose argument may be a pattern or a script (`grep`, `sed`, `awk`) is still listed — the
 * pattern resolves to a project path that is not a secret, so only the file operand can trip the rule.
 */
export const SECRET_READERS = new Set([
  "ag",
  "awk",
  "base64",
  "bat",
  "cat",
  "column",
  "cut",
  "diff",
  "egrep",
  "fgrep",
  "fold",
  "gawk",
  "grep",
  "head",
  "jq",
  "less",
  "mawk",
  "more",
  "nl",
  "od",
  "paste",
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

/** An interpreter and the flags that hand it a program inline, on the command line the gate can read. */
const INLINE_PROGRAM_FLAGS: Record<string, readonly string[]> = {
  python: ["-c"],
  python2: ["-c"],
  python3: ["-c"],
  node: ["-e", "--eval", "-p", "--print"],
  nodejs: ["-e", "--eval", "-p", "--print"],
  bun: ["-e", "--eval", "-p", "--print"],
  deno: ["eval"],
  ruby: ["-e"],
  perl: ["-e", "-E"],
  php: ["-r"],
};

// why: the path-shaped runs inside a program's text. `open('.env')` and `readFileSync("/home/me/.ssh/id_rsa")` both
// name the file as a literal the gate can resolve, the same way it resolves a reader's operand.
const PATH_TOKEN = /[~./A-Za-z0-9_-]*[A-Za-z0-9_.-]+/g;

/** The secret path an inline program names, if it names one. */
export function inlineProgramSecret(
  verb: string,
  args: readonly ShellWord[],
  projectDir: string,
): string | null {
  const flags = INLINE_PROGRAM_FLAGS[verb];
  if (!flags) {
    return null;
  }
  const index = args.findIndex((word) => flags.includes(word.text));
  const program = index === -1 ? undefined : args[index + 1];
  if (!program) {
    return null;
  }
  for (const match of program.text.matchAll(PATH_TOKEN)) {
    const resolved = resolveTarget(projectDir, match[0]);
    if (isSecretPath(resolved)) {
      return resolved;
    }
  }
  return null;
}

type StoredSecretRule = { verb: string; words: readonly string[]; label: string; also?: RegExp };

/**
 * The commands whose whole job is to print a stored secret. The value leaves the store and lands in the
 * transcript, which is exactly what keeping it in a store was meant to prevent.
 *
 * invariant: matched by verb plus the subcommand words, in order, so `op signin`, `kubectl get pods` or
 * `vault status` stay allowed. `also` narrows a rule to the flag that makes the command print the value.
 */
const STORED_SECRET_RULES: readonly StoredSecretRule[] = [
  { verb: "isys", words: ["vault", "get"], label: "isys vault get" },
  { verb: "op", words: ["read"], label: "op read" },
  { verb: "op", words: ["item", "get"], label: "op item get" },
  { verb: "op", words: ["document", "get"], label: "op document get" },
  {
    verb: "security",
    words: ["find-generic-password"],
    label: "security find-generic-password",
    also: /^-[a-z]*[wg]/,
  },
  {
    verb: "security",
    words: ["find-internet-password"],
    label: "security find-internet-password",
    also: /^-[a-z]*[wg]/,
  },
  { verb: "kubectl", words: ["get", "secret"], label: "kubectl get secret -o", also: /^(-o|--output)/ },
  { verb: "kubectl", words: ["get", "secrets"], label: "kubectl get secrets -o", also: /^(-o|--output)/ },
  {
    verb: "aws",
    words: ["secretsmanager", "get-secret-value"],
    label: "aws secretsmanager get-secret-value",
  },
  {
    verb: "aws",
    words: ["ssm", "get-parameter"],
    label: "aws ssm get-parameter --with-decryption",
    also: /^--with-decryption$/,
  },
  {
    verb: "aws",
    words: ["ssm", "get-parameters"],
    label: "aws ssm get-parameters --with-decryption",
    also: /^--with-decryption$/,
  },
  { verb: "gcloud", words: ["secrets", "versions", "access"], label: "gcloud secrets versions access" },
  { verb: "vault", words: ["kv", "get"], label: "vault kv get" },
  { verb: "vault", words: ["read"], label: "vault read" },
  { verb: "az", words: ["keyvault", "secret", "show"], label: "az keyvault secret show" },
  { verb: "gh", words: ["auth", "token"], label: "gh auth token" },
  { verb: "pass", words: ["show"], label: "pass show" },
  { verb: "keepassxc-cli", words: ["show"], label: "keepassxc-cli show" },
  { verb: "doppler", words: ["secrets", "get"], label: "doppler secrets get" },
  { verb: "heroku", words: ["config:get"], label: "heroku config:get" },
];

function startsWithWords(operands: readonly string[], words: readonly string[]): boolean {
  return words.every((word, index) => operands[index] === word);
}

/** The stored-secret command this segment runs, if it runs one. */
export function storedSecretCommand(verb: string, args: readonly ShellWord[]): string | null {
  const texts = args.map((word) => word.text);
  const operands = texts.filter((text) => !text.startsWith("-"));
  for (const rule of STORED_SECRET_RULES) {
    if (rule.verb !== verb || !startsWithWords(operands, rule.words)) {
      continue;
    }
    const also = rule.also;
    if (also === undefined || texts.some((text) => also.test(text))) {
      return rule.label;
    }
  }
  return null;
}

/** why: these take their first operand as a pattern, so `grep -rn credentials src` searches for a word. */
const SEARCH_VERBS = new Set(["ack", "ag", "egrep", "fgrep", "grep", "rg"]);
const PATTERN_FLAGS = new Set(["-e", "--regexp", "-f", "--file"]);

/**
 * The operands a reader would open as files.
 *
 * hazard: `grep -rn credentials src` was refused, because the pattern resolved to `<project>/credentials` — a
 * basename this rule treats as a secret. A search verb's first operand is its pattern unless `-e` or `-f` gave one.
 */
export function readerOperands(verb: string, args: readonly ShellWord[]): ShellWord[] {
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

function secretIn(projectDir: string, text: string): string | null {
  const resolved = resolveTarget(projectDir, text);
  return isSecretPath(resolved) ? resolved : null;
}

function firstSecret(projectDir: string, words: readonly ShellWord[]): string | null {
  for (const word of words) {
    const found = secretIn(projectDir, word.text);
    if (found) {
      return found;
    }
  }
  return null;
}

/** why: `git add .env` names the file; these subcommands print what is in it. */
const GIT_CONTENT_SUBCOMMANDS = new Set(["annotate", "blame", "cat-file", "diff", "grep", "show"]);
const GIT_PATCH_FLAGS = new Set(["-p", "-u", "--patch"]);

function gitPrintsContent(args: readonly ShellWord[]): boolean {
  const sub = args.find((word) => !word.text.startsWith("-"))?.text;
  if (sub === undefined) {
    return false;
  }
  return (
    GIT_CONTENT_SUBCOMMANDS.has(sub) || (sub === "log" && args.some((word) => GIT_PATCH_FLAGS.has(word.text)))
  );
}

// why: `git show HEAD:.env` names the file after the revision, inside one word.
function gitContentSecret(projectDir: string, args: readonly ShellWord[]): string | null {
  if (!gitPrintsContent(args)) {
    return null;
  }
  const paths = args.slice(1).map((word) => ({ ...word, text: word.text.slice(word.text.indexOf(":") + 1) }));
  return firstSecret(projectDir, readerOperands("git", paths));
}

/** why: a copy under an ordinary name is a credential this rule no longer recognises by name. */
const COPY_VERBS = new Set(["cp", "ln", "mv", "rsync"]);

// why: `cp .env.example .env` is how a project is set up, and `cp .env .env.bak` keeps the copy recognisable.
// Only a copy that lands under a name this rule cannot see is refused.
function copiesOutOfSight(projectDir: string, args: readonly ShellWord[]): string | null {
  const paths = readerOperands("", args);
  const destination = paths.at(-1);
  if (paths.length < 2 || !destination || secretIn(projectDir, destination.text)) {
    return null;
  }
  return firstSecret(projectDir, paths.slice(0, -1));
}

const SHELLS = new Set(["ash", "bash", "dash", "fish", "ksh", "sh", "zsh"]);
const AWKS = new Set(["awk", "gawk", "mawk"]);
const PATH_PIECE = /[A-Za-z0-9_.~/@+-]+/g;

// invariant: inside program text, a bare word is a path only when it is written like one. `credentials = 1` names a
// variable, and a floor with no switch cannot afford to read every word as a file.
function secretInProgram(projectDir: string, text: string): string | null {
  for (const piece of text.match(PATH_PIECE) ?? []) {
    const pathLike = piece.includes("/") || piece.startsWith(".") || piece.startsWith("~");
    const found = pathLike ? secretIn(projectDir, piece) : null;
    if (found) {
      return found;
    }
  }
  return null;
}

// why: `bash -c "cat .env"` and an awk program's `getline < ".env"` carry the read inside one quoted word.
function programSecret(projectDir: string, verb: string, args: readonly ShellWord[]): string | null {
  if (SHELLS.has(verb)) {
    const index = args.findIndex((word) => word.text === "-c");
    const program = index === -1 ? undefined : args[index + 1];
    return program ? secretInProgram(projectDir, program.text) : null;
  }
  if (AWKS.has(verb)) {
    const program = args.find((word) => !word.text.startsWith("-"));
    return program ? secretInProgram(projectDir, program.text) : null;
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

// why: a reader verb is one shape of a read; a redirect, a git dump, a copy and a shell or awk program are the others.
function secretByVerb(projectDir: string, verb: string, args: readonly ShellWord[]): string | null {
  if (verb === "git") {
    return gitContentSecret(projectDir, args);
  }
  if (COPY_VERBS.has(verb)) {
    return copiesOutOfSight(projectDir, args);
  }
  return programSecret(projectDir, verb, args);
}

export function shapedSecretRead(
  projectDir: string,
  verb: string,
  args: readonly ShellWord[],
  words: readonly ShellWord[],
): string | null {
  return secretByVerb(projectDir, verb, args) ?? redirectedSecret(projectDir, words);
}

const SUBSTITUTION = /\$\(([^)]*)\)|`([^`]*)`/g;

/** why: `echo "$(cat .env)"` carries the read inside a word the gate otherwise skips as unresolved. */
export function substitutedCommands(words: readonly ShellWord[]): string[] {
  const out: string[] = [];
  for (const word of words) {
    for (const match of word.text.matchAll(SUBSTITUTION)) {
      out.push(match[1] ?? match[2] ?? "");
    }
  }
  return out;
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
  const map: Record<string, string> = { "*": ".*", "?": ".", "{": "(", "}": ")", ",": "|" };
  let source = "";
  for (const char of glob) {
    source += map[char] ?? char.replace(/[.+^$()|[\]\\]/g, "\\$&");
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
