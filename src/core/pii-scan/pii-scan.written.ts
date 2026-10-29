import type { AddedLine } from "../../platform/git.ts";
import { scanForPii } from "./pii-scan.service.ts";
import { classifyPiiSource } from "./pii-scan.source.ts";
import type { CompiledPiiTemplate } from "./pii-scan.template.ts";

/** why: a finding names where and what kind, never the value — it is shown to the agent and written to the log. */
export type WrittenPii = { file: string; line: number; kind: string };

function globToRegExp(glob: string): RegExp {
  let source = "";
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index] ?? "";
    if (char === "*" && glob[index + 1] === "*") {
      source += ".*";
      index += glob[index + 2] === "/" ? 2 : 1;
    } else if (char === "*") {
      source += "[^/]*";
    } else if (char === "?") {
      source += "[^/]";
    } else {
      source += char.replace(/[.+^$()|[\]{}\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${source}$`);
}

export function isFixturePath(file: string, template: CompiledPiiTemplate): boolean {
  const normalized = file.replace(/\\/g, "/");
  return template.fixturePaths.some((glob) => globToRegExp(glob).test(normalized));
}

/**
 * The personal data an agent's own additions carry.
 *
 * invariant: in a source file only a value whose shape proves itself counts — a mailbox, a valid document, a real
 * card. A field name beside a string (`name: "Ana"`) cannot be told from a fixture, so it never blocks a turn; in a
 * config, log or data file it does, because no one types a sample customer into those by accident.
 */
export function findAddedPii(added: readonly AddedLine[], template: CompiledPiiTemplate): WrittenPii[] {
  const out: WrittenPii[] = [];
  for (const line of added) {
    if (isFixturePath(line.file, template)) {
      continue;
    }
    const source = classifyPiiSource({ filePath: line.file });
    const matches = scanForPii(line.text, template, {
      fields: source !== "source-file" && source !== "other",
    });
    for (const match of matches) {
      out.push({ file: line.file, line: line.line, kind: match.kind });
    }
  }
  return out;
}

export function writtenPiiFollowup(findings: readonly WrittenPii[]): string {
  const listed = findings
    .slice(0, 20)
    .map((finding) => `  - ${finding.file}:${finding.line} (${finding.kind})`)
    .join("\n");
  const more = findings.length > 20 ? `\n  … and ${findings.length - 20} more` : "";
  return [
    "[PII-HYGIENE written] This turn added personal data to the repository:",
    `${listed}${more}`,
    "Personal data belongs in the database or the API, not in code, comments, config or logs. Replace each value with a fixture: a reserved domain (example.com, .invalid, .test), an invalid-checksum document, an issuer test card. If the data is a legitimate seed, ask the operator to list its path under `fixtures.paths` in `.tlc/harness/pii.json`.",
  ].join("\n");
}
