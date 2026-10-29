import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline/promises";
import { scanForPii } from "../src/core/pii-scan/pii-scan.service.ts";
import { classifyPiiSource } from "../src/core/pii-scan/pii-scan.source.ts";
import {
  isSchemaCandidate,
  type PiiCandidate,
  type SchemaFile,
  schemaPatterns,
  suggestPiiTemplate,
} from "../src/core/pii-scan/pii-scan.suggest.ts";
import {
  compilePiiTemplate,
  loadPiiTemplate,
  type PiiTemplateFile,
} from "../src/core/pii-scan/pii-scan.template.ts";
import { emitJson, takeJsonFlag } from "../src/platform/cli-output.ts";
import { listProjectFiles } from "../src/platform/git.ts";
import { piiTemplatePath } from "../src/platform/paths.ts";
import { readStdinText } from "../src/platform/process.ts";

function usage(): void {
  console.log("usage: tlc harness pii suggest [--candidates <file|->] | test <file|-> | apply <file>");
}

// why: a schema file over this size is a data dump, not a schema, and reading it would be reading the data.
const MAX_SCHEMA_BYTES = 512 * 1024;

function readSchemas(root: string, paths: readonly string[]): SchemaFile[] {
  const files: SchemaFile[] = [];
  for (const path of paths.filter(isSchemaCandidate)) {
    try {
      const text = readFileSync(join(root, path), "utf8");
      if (text.length <= MAX_SCHEMA_BYTES && schemaPatterns(path, text).length > 0) {
        files.push({ path, text });
      }
    } catch {}
  }
  return files;
}

const MODES = new Set(["pseudonym", "mask"]);

/**
 * invariant: what a reader of the code proposed is only names, kinds and where it saw them. Anything else in the
 * input is dropped here, so a candidate list can never smuggle a pattern, a pack or a fixture into the template.
 */
export function parseCandidates(raw: string): PiiCandidate[] {
  const parsed: unknown = JSON.parse(raw);
  const list = Array.isArray(parsed) ? parsed : [];
  const out: PiiCandidate[] = [];
  for (const item of list) {
    const entry = typeof item === "string" ? { name: item } : (item as Record<string, unknown>);
    if (typeof entry?.name !== "string" || entry.name.trim() === "") {
      continue;
    }
    out.push({
      name: entry.name,
      ...(typeof entry.kind === "string" && /^[a-z][\w-]{0,31}$/.test(entry.kind)
        ? { kind: entry.kind }
        : {}),
      ...(typeof entry.mode === "string" && MODES.has(entry.mode)
        ? { mode: entry.mode as PiiCandidate["mode"] }
        : {}),
      ...(typeof entry.evidence === "string" ? { evidence: entry.evidence.slice(0, 160) } : {}),
    });
  }
  return out;
}

function takeOption(argv: string[], flag: string): { value: string | undefined; rest: string[] } {
  const at = argv.indexOf(flag);
  if (at === -1) {
    return { value: undefined, rest: argv };
  }
  return { value: argv[at + 1], rest: [...argv.slice(0, at), ...argv.slice(at + 2)] };
}

async function suggest(root: string, json: boolean, candidatesFrom: string | undefined): Promise<void> {
  const paths = await listProjectFiles(root);
  const schemas = readSchemas(root, paths);
  const candidates =
    candidatesFrom === undefined
      ? []
      : parseCandidates(
          candidatesFrom === "-" ? await readStdinText() : readFileSync(candidatesFrom, "utf8"),
        );
  const suggestion = suggestPiiTemplate(schemas, paths, candidates);
  if (json) {
    emitJson(suggestion);
    return;
  }
  console.log(`# Proposed ${piiTemplatePath(root)} — review, edit, and save it yourself.`);
  console.log(JSON.stringify(suggestion.template, null, 2));
  // why: an empty proposal with no reason reads as "this project holds no personal data", which is never what it means.
  if (schemas.length === 0 && candidates.length === 0) {
    console.log(
      "\n# No schema file found (SQL, migrations, Prisma, GraphQL, OpenAPI, Protobuf, Avro, Liquibase, or ORM classes\n" +
        "  in Java/Kotlin, C#, Go, Python, Ruby, PHP, Elixir, TypeScript/JavaScript). Only the default packs are\n" +
        "  proposed — ask the agent to run the harness-pii skill, or list the personal fields under `fields`.",
    );
    return;
  }
  console.log("\n# Evidence");
  for (const item of suggestion.evidence) {
    const where = item.files.length > 0 ? ` — ${item.files.join(", ")}` : "";
    console.log(`  ${item.name} → ${item.via}${where}`);
  }
}

/**
 * why positions and kinds only: this is how an operator calibrates the template against a real export, and printing
 * the values back would put the export on the terminal and in its scrollback.
 */
async function testText(root: string, target: string | undefined, json: boolean): Promise<void> {
  if (!target) {
    usage();
    process.exit(1);
  }
  const text = target === "-" ? await readStdinText() : readFileSync(target, "utf8");
  const template = loadPiiTemplate(root);
  const source = target === "-" ? "other" : classifyPiiSource({ filePath: target });
  const matches = scanForPii(text, template, { fields: source !== "source-file" });
  const located = matches.map((match) => {
    const before = text.slice(0, match.start);
    const line = before.split("\n").length;
    return { line, column: match.start - before.lastIndexOf("\n"), kind: match.kind, mode: match.mode };
  });
  if (json) {
    emitJson({
      template: template.source,
      packs: template.packs,
      errors: template.errors,
      source,
      matches: located,
    });
    return;
  }
  console.log(`template: ${template.source} (${template.packs.join(", ")}) · source: ${source}`);
  for (const error of template.errors) {
    console.log(`  error: ${error}`);
  }
  for (const match of located) {
    console.log(`  ${match.line}:${match.column}  ${match.kind}${match.mode === "mask" ? " (mask)" : ""}`);
  }
  console.log(`${located.length} value(s) would be pseudonymised; none are printed.`);
}

const TEMPLATE_KEYS = new Set(["$schema", "extends", "fields", "patterns", "fixtures", "keep"]);

export type ApplyPlan =
  | { ok: false; errors: string[] }
  | { ok: true; next: string; diff: string[]; unchanged: boolean };

// why: a template is short, so a plain longest-common-subsequence over lines is exact and needs no dependency.
export function lineDiff(before: readonly string[], after: readonly string[]): string[] {
  const width = after.length + 1;
  const common = new Array<number>((before.length + 1) * width).fill(0);
  const at = (i: number, j: number): number => common[i * width + j] ?? 0;
  for (let i = before.length - 1; i >= 0; i -= 1) {
    for (let j = after.length - 1; j >= 0; j -= 1) {
      common[i * width + j] =
        before[i] === after[j] ? at(i + 1, j + 1) + 1 : Math.max(at(i + 1, j), at(i, j + 1));
    }
  }
  const out: string[] = [];
  let i = 0;
  let j = 0;
  while (i < before.length || j < after.length) {
    const takeAdded = i >= before.length || (j < after.length && at(i, j + 1) >= at(i + 1, j));
    if (i < before.length && j < after.length && before[i] === after[j]) {
      out.push(`  ${before[i]}`);
      i += 1;
      j += 1;
    } else if (takeAdded) {
      out.push(`+ ${after[j]}`);
      j += 1;
    } else {
      out.push(`- ${before[i]}`);
      i += 1;
    }
  }
  return out;
}

/**
 * What applying a proposed template would do: refuse it, or the exact file and the change.
 *
 * invariant: the proposal is compiled by the same compiler the hooks use, and a template with any error is refused
 * whole. A hook degrades a broken template to the defaults; a file the operator just chose to install must not
 * silently do less than it says.
 */
export function planApply(current: string | null, proposed: string): ApplyPlan {
  let parsed: unknown;
  try {
    parsed = JSON.parse(proposed);
  } catch (error) {
    return { ok: false, errors: [`not JSON: ${(error as Error).message}`] };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, errors: ["a template is a JSON object"] };
  }
  const unknown = Object.keys(parsed).filter((key) => !TEMPLATE_KEYS.has(key));
  const errors = unknown.map((key) => `unknown key \`${key}\``);
  compilePiiTemplate(parsed as PiiTemplateFile, errors);
  if (errors.length > 0) {
    return { ok: false, errors };
  }
  const next = `${JSON.stringify(parsed, null, 2)}\n`;
  const before = current === null ? [] : current.replace(/\n$/, "").split("\n");
  const diff = lineDiff(before, next.replace(/\n$/, "").split("\n"));
  return { ok: true, next, diff, unchanged: current === next };
}

async function confirm(question: string): Promise<boolean> {
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return /^y(es)?$/i.test((await prompt.question(question)).trim());
  } finally {
    prompt.close();
  }
}

/**
 * why a command, not a copy: it validates, shows the change and asks before it writes. The floor refuses it to the
 * agent like every other policy write, so the skill can only hand the operator this one line.
 *
 * invariant: no flag skips the question, the same rule as `policy accept` — a terminal is the operator's, and a
 * script or an agent shell is not one.
 */
async function apply(root: string, source: string | undefined): Promise<void> {
  if (!source) {
    usage();
    process.exit(1);
  }
  const target = piiTemplatePath(root);
  const current = existsSync(target) ? readFileSync(target, "utf8") : null;
  const plan = planApply(current, readFileSync(source, "utf8"));
  if (!plan.ok) {
    console.error(`pii apply: refused — ${source} does not compile:`);
    for (const error of plan.errors) {
      console.error(`  ${error}`);
    }
    process.exit(1);
  }
  if (plan.unchanged) {
    console.log(`pii apply: ${target} already matches — nothing to do.`);
    return;
  }
  console.log(`# ${current === null ? "create" : "update"} ${target}`);
  for (const line of plan.diff) {
    console.log(line);
  }
  if (!process.stdin.isTTY) {
    console.error(
      "pii apply: needs an interactive terminal — the PII template is the operator's to install.",
    );
    process.exit(1);
  }
  if (!(await confirm("\nWrite this template? [y/N] "))) {
    console.log("pii apply: nothing written.");
    return;
  }
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, plan.next);
  console.log(`pii apply: wrote ${target}.`);
  console.log("  Commit it so the template is reviewed like the rest of the policy.");
  console.log(
    `  A session already open reports the policy changed under it; \`tlc harness policy accept ${target}\` records it.`,
  );
}

async function main(argv: string[]): Promise<void> {
  const { json, rest: afterJson } = takeJsonFlag(argv);
  const { value: candidatesFrom, rest } = takeOption(afterJson, "--candidates");
  const root = process.env.TLC_PROJECT_DIR ?? process.cwd();
  const [cmd, target] = rest;
  if (cmd === "suggest") {
    await suggest(root, json, candidatesFrom);
    return;
  }
  if (cmd === "apply") {
    await apply(root, target);
    return;
  }
  if (cmd === "test") {
    await testText(root, target, json);
    return;
  }
  usage();
}

if (import.meta.main) {
  await main(process.argv.slice(2));
}
