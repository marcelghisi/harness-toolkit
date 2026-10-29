import { readFileSync } from "node:fs";
import { join } from "node:path";
import { scanForPii } from "../src/core/pii-scan/pii-scan.service.ts";
import { classifyPiiSource } from "../src/core/pii-scan/pii-scan.source.ts";
import { isSchemaFile, type SchemaFile, suggestPiiTemplate } from "../src/core/pii-scan/pii-scan.suggest.ts";
import { loadPiiTemplate } from "../src/core/pii-scan/pii-scan.template.ts";
import { emitJson, takeJsonFlag } from "../src/platform/cli-output.ts";
import { listProjectFiles } from "../src/platform/git.ts";
import { piiTemplatePath } from "../src/platform/paths.ts";
import { readStdinText } from "../src/platform/process.ts";

function usage(): void {
  console.log("usage: tlc harness pii suggest | test <file|->");
}

// why: a schema file over this size is a data dump, not a schema, and reading it would be reading the data.
const MAX_SCHEMA_BYTES = 512 * 1024;

function readSchemas(root: string, paths: readonly string[]): SchemaFile[] {
  const files: SchemaFile[] = [];
  for (const path of paths.filter(isSchemaFile)) {
    try {
      const text = readFileSync(join(root, path), "utf8");
      if (text.length <= MAX_SCHEMA_BYTES) {
        files.push({ path, text });
      }
    } catch {}
  }
  return files;
}

async function suggest(root: string, json: boolean): Promise<void> {
  const paths = await listProjectFiles(root);
  const schemas = readSchemas(root, paths);
  const suggestion = suggestPiiTemplate(schemas, paths);
  if (json) {
    emitJson(suggestion);
    return;
  }
  console.log(`# Proposed ${piiTemplatePath(root)} — review, edit, and save it yourself.`);
  console.log(JSON.stringify(suggestion.template, null, 2));
  // why: an empty proposal with no reason reads as "this project holds no personal data", which is never what it means.
  if (schemas.length === 0) {
    console.log(
      "\n# No schema file found (SQL, Prisma, GraphQL, OpenAPI, *schema*/*model*/*types* sources, migrations/).\n" +
        "  Only the default packs are proposed — list the personal fields yourself under `fields`.",
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
  const { json, rest } = takeJsonFlag(argv);
  const root = process.env.TLC_PROJECT_DIR ?? process.cwd();
  const [cmd, target] = rest;
  if (cmd === "suggest") {
    await suggest(root, json);
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
