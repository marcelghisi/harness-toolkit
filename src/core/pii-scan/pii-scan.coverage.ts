import type { AddedLine } from "../../platform/git.ts";
import { labelFor } from "./pii-scan.service.ts";
import { fieldsIn, looksPersonal, packsFor, type SchemaFile, schemaPatterns } from "./pii-scan.suggest.ts";
import type { CompiledPiiTemplate } from "./pii-scan.template.ts";

/** A schema field that looks personal and that the project's template would not mask. */
export type UncoveredField = {
  field: string;
  file: string;
  line?: number;
  /** why: when a pack already labels the field, enabling the pack is the fix, not a custom field. */
  packs: string[];
};

function uncovered(field: string, template: CompiledPiiTemplate): boolean {
  return looksPersonal(field) && !template.ignore.has(field) && labelFor(field, template) === undefined;
}

/**
 * Every personal-looking field the schema declares and the template does not cover.
 *
 * invariant: one entry per field, at the first file that declares it, so a column repeated across a model, a
 * migration and a DTO is one decision, not three.
 */
export function uncoveredFields(
  files: readonly SchemaFile[],
  template: CompiledPiiTemplate,
): UncoveredField[] {
  const out = new Map<string, UncoveredField>();
  for (const file of [...files].sort((a, b) => a.path.localeCompare(b.path))) {
    for (const field of fieldsIn(file.path, file.text)) {
      if (!out.has(field) && uncovered(field, template)) {
        out.set(field, { field, file: file.path, packs: packsFor(field) });
      }
    }
  }
  return [...out.values()];
}

/**
 * The uncovered fields a turn's own additions declare.
 *
 * why per added line with the whole file at hand: the ORM marker that makes a class a schema is usually far from
 * the line that adds a column, and a field the file already had is not this turn's to report.
 */
export function uncoveredInAdded(
  added: readonly AddedLine[],
  readFile: (path: string) => string | null,
  template: CompiledPiiTemplate,
): UncoveredField[] {
  const texts = new Map<string, string | null>();
  const out = new Map<string, UncoveredField>();
  for (const line of added) {
    if (!texts.has(line.file)) {
      texts.set(line.file, readFile(line.file));
    }
    const text = texts.get(line.file);
    if (!text || schemaPatterns(line.file, text).length === 0) {
      continue;
    }
    for (const field of fieldsIn(line.file, text, line.text)) {
      if (!out.has(field) && uncovered(field, template)) {
        out.set(field, { field, file: line.file, line: line.line, packs: packsFor(field) });
      }
    }
  }
  return [...out.values()];
}

export function describeUncovered(field: UncoveredField): string {
  const where = field.line === undefined ? field.file : `${field.file}:${field.line}`;
  const fix = field.packs.length > 0 ? `enable ${field.packs.join(" or ")}` : "add it to `fields`";
  return `${field.field} — ${where} (${fix}, or list it under \`ignore\` if it is not personal)`;
}

export function uncoveredFollowup(fields: readonly UncoveredField[]): string {
  const listed = fields
    .slice(0, 20)
    .map((field) => `  - ${describeUncovered(field)}`)
    .join("\n");
  const more = fields.length > 20 ? `\n  … and ${fields.length - 20} more` : "";
  return [
    "[PII-HYGIENE coverage] This turn added schema fields that look personal and are not in the project's PII template, so their values would reach the model unmasked:",
    `${listed}${more}`,
    "Run the harness-pii skill to propose the template update, and tell the operator to install it with `tlc harness pii apply <file>`. Do not edit the template yourself.",
  ].join("\n");
}
