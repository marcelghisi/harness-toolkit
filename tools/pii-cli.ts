import { readFileSync } from "node:fs";
import { join } from "node:path";
import { scanForPii } from "../src/core/pii-scan/pii-scan.service.ts";
import { classifyPiiSource } from "../src/core/pii-scan/pii-scan.source.ts";
import {
  isSchemaCandidate,
  type PiiCandidate,
  type SchemaFile,
  schemaPatterns,
  suggestPiiTemplate,
} from "../src/core/pii-scan/pii-scan.suggest.ts";
import { loadPiiTemplate } from "../src/core/pii-scan/pii-scan.template.ts";
import { emitJson, takeJsonFlag } from "../src/platform/cli-output.ts";
import { listProjectFiles } from "../src/platform/git.ts";
import { piiTemplatePath } from "../src/platform/paths.ts";
import { readStdinText } from "../src/platform/process.ts";

function usage(): void {
  console.log("usage: tlc harness pii suggest [--candidates <file|->] | test <file|->");
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

async function main(argv: string[]): Promise<void> {
  const { json, rest: afterJson } = takeJsonFlag(argv);
  const { value: candidatesFrom, rest } = takeOption(afterJson, "--candidates");
  const root = process.env.TLC_PROJECT_DIR ?? process.cwd();
  const [cmd, target] = rest;
  if (cmd === "suggest") {
    await suggest(root, json, candidatesFrom);
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
