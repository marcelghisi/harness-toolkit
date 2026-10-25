import { extname } from "node:path";

/**
 * Why a secret was in the output, which is the defect worth fixing — the mask only hides the symptom.
 *
 * invariant: decided from what the hook already has (the event, the command, the file) and never from the value
 * itself, so a classification can be recorded and shown without carrying the secret anywhere.
 */
export type LeakCause = "logged-credential" | "argv-credential" | "env-dump" | "hardcoded" | "other";

export type LeakInput = {
  command?: string | undefined;
  filePath?: string | undefined;
  // why: whether the command line itself carried a secret is decided by the caller's scan, which holds the values.
  commandCarriesSecret: boolean;
};

// why: the readers that show a log, and the platforms whose `logs` subcommand prints one.
export const LOG_READERS =
  /(^|[\s;&|(])(cat|tail|head|less|more|grep|rg|awk|sed|bat|zcat)\b[^;&|]*(\.log\b|(^|[\s/])logs?\/)/;
export const LOG_COMMANDS =
  /(^|[\s;&|(])(docker(\s+compose)?\s+logs|kubectl\s+logs|journalctl|pm2\s+logs|heroku\s+logs|fly\s+logs)\b/;
const ENV_DUMPS = /(^|[\s;&|(])(env|printenv|set|export\s+-p|declare\s+-x)\s*($|[;&|)])/;

// why: the flags and headers that put a credential on a command line, where shell history and `ps` keep it.
const ARGV_CREDENTIAL =
  /(\s-p\S+|--pass(word)?[=\s]|--token[=\s]|--api-key[=\s]|Authorization:|PGPASSWORD=|MYSQL_PWD=)/i;

const SOURCE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".go",
  ".java",
  ".kt",
  ".rb",
  ".php",
  ".cs",
  ".rs",
  ".swift",
  ".scala",
  ".sh",
  ".yaml",
  ".yml",
  ".json",
  ".toml",
  ".ini",
  ".properties",
  ".xml",
  ".tf",
  ".conf",
]);

export function classifyLeak(input: LeakInput): LeakCause {
  const command = input.command ?? "";
  if (command !== "") {
    if (input.commandCarriesSecret || ARGV_CREDENTIAL.test(command)) {
      return "argv-credential";
    }
    if (LOG_READERS.test(command) || LOG_COMMANDS.test(command)) {
      return "logged-credential";
    }
    if (ENV_DUMPS.test(command)) {
      return "env-dump";
    }
    return "other";
  }
  if (input.filePath && SOURCE_EXTENSIONS.has(extname(input.filePath).toLowerCase())) {
    return "hardcoded";
  }
  if (input.filePath && /\.log$/i.test(input.filePath)) {
    return "logged-credential";
  }
  return "other";
}

/**
 * why these words: the developer rarely needs the value, only which secret was loaded and whether it works — so
 * every fix points at metadata, a type that cannot print, or the logger's own redaction, never at another way to
 * read the value. And it says to hand the fix back when it is outside the task, so the advice cannot hijack a turn.
 */
const ADVICE: Record<LeakCause, string> = {
  "logged-credential":
    "A credential in a log means code logs it — at any level, debug included. Fix the code that writes it: log metadata instead of the value (present, length, source, an HMAC fingerprint), keep the value in a type that cannot print, or turn on the logger's redaction.",
  "argv-credential":
    "The command line carried a credential, and shell history and the process list keep it. Pass it through an environment variable or a config file the program reads at runtime.",
  "env-dump":
    'Dumping the environment prints every credential in it. Check a variable\'s presence instead, e.g. `[ -n "$VAR" ] && echo set`.',
  hardcoded:
    "This file holds a literal credential. Move it to an environment variable or the project's secret store, read it at runtime, and rotate it if the file was ever committed.",
  other:
    "A tool's output carried a credential. Find where it came from before relying on that tool's output again.",
};

export function leakAdvice(cause: LeakCause, kinds: readonly string[], subject: string): string {
  const names = [...new Set(kinds)].join(", ");
  return [
    `[SECRET-HYGIENE ${cause}] ${subject} exposed ${names}; the value was masked.`,
    ADVICE[cause],
    "Do not try to read the value another way. If fixing this is outside your task, tell the operator instead.",
  ].join(" ");
}
