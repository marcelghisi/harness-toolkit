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
