import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { piiTemplatePath } from "../../platform/paths.ts";
import { tokenizeShell } from "../floor/floor.tokenize.ts";
import { DEFAULT_PACKS, type PiiMode, packById } from "./pii-scan.packs.ts";
import { isValidatorName, VALIDATORS } from "./pii-scan.validators.ts";

export type KeepAttribute = "email-domain" | "phone-country" | "card-last4";

const KEEP_ATTRIBUTES: readonly KeepAttribute[] = ["email-domain", "phone-country", "card-last4"];

export type CompiledDetector = {
  kind: string;
  regex: RegExp;
  validate: ((text: string) => boolean) | null;
  mode: PiiMode;
};

export type LabelRule = { kind: string; mode: PiiMode };

export type CompiledPiiTemplate = {
  source: "file" | "default";
  packs: string[];
  detectors: CompiledDetector[];
  labels: Map<string, LabelRule>;
  fixtureDomains: string[];
  fixturePaths: string[];
  keep: Set<KeepAttribute>;
  /**
   * Field names the operator reviewed and decided are not personal.
   *
   * invariant: only the coverage check reads this. It silences "this new field looks personal" and never unmasks a
   * value — a label a pack covers is still masked even when it is listed here.
   */
  ignore: Set<string>;
  /** why: a broken template is reported by `doctor` and never takes a hook down — the defaults still apply. */
  errors: string[];
};

type FieldEntry = string | { name: string; kind?: string; mode?: PiiMode };
type PatternEntry = { kind: string; regex: string; validate?: string; mode?: PiiMode };

export type PiiTemplateFile = {
  extends?: string[];
  fields?: FieldEntry[];
  patterns?: PatternEntry[];
  fixtures?: { domains?: string[]; paths?: string[] };
  keep?: string[];
  ignore?: string[];
};

/**
 * invariant: one spelling per field name, so `Customer-Email`, `customer_email` and `customerEmail` all look up the
 * same label — and accents fold, so `endereço` and `endereco` are one name.
 */
export function normalizeLabel(name: string): string {
  return name
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function compilePacks(ids: readonly string[], errors: string[], out: CompiledPiiTemplate): void {
  // why: `global` carries the shapes every project has — an email is personal data in any country.
  const wanted = ["global", ...ids.filter((id) => id !== "global")];
  for (const id of wanted) {
    const pack = packById(id);
    if (!pack) {
      errors.push(`unknown pack \`${id}\``);
      continue;
    }
    out.packs.push(id);
    const mode = pack.mode ?? "pseudonym";
    for (const detector of pack.detectors ?? []) {
      out.detectors.push({
        kind: detector.kind,
        regex: new RegExp(detector.pattern, "g"),
        validate: detector.validate ? VALIDATORS[detector.validate] : null,
        mode,
      });
    }
    for (const [label, kind] of Object.entries(pack.labels ?? {})) {
      out.labels.set(label, { kind, mode });
    }
  }
}

function compileFields(fields: readonly FieldEntry[], out: CompiledPiiTemplate): void {
  for (const field of fields) {
    const name = typeof field === "string" ? field : field.name;
    const kind = typeof field === "string" ? "custom" : (field.kind ?? "custom");
    const mode = typeof field === "string" ? "pseudonym" : (field.mode ?? "pseudonym");
    out.labels.set(normalizeLabel(name), { kind, mode });
  }
}

function compilePatterns(
  patterns: readonly PatternEntry[],
  errors: string[],
  out: CompiledPiiTemplate,
): void {
  for (const pattern of patterns) {
    if (pattern.validate !== undefined && !isValidatorName(pattern.validate)) {
      errors.push(`pattern \`${pattern.kind}\`: unknown validate \`${pattern.validate}\``);
      continue;
    }
    try {
      out.detectors.push({
        kind: pattern.kind,
        regex: new RegExp(pattern.regex, "g"),
        validate: pattern.validate && isValidatorName(pattern.validate) ? VALIDATORS[pattern.validate] : null,
        mode: pattern.mode ?? "pseudonym",
      });
    } catch (error) {
      errors.push(`pattern \`${pattern.kind}\`: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

function compileKeep(keep: readonly string[] | undefined, errors: string[]): Set<KeepAttribute> {
  if (keep === undefined) {
    return new Set(KEEP_ATTRIBUTES);
  }
  const out = new Set<KeepAttribute>();
  for (const attribute of keep) {
    const known = KEEP_ATTRIBUTES.find((candidate) => candidate === attribute);
    if (known) {
      out.add(known);
    } else {
      errors.push(`unknown keep attribute \`${attribute}\``);
    }
  }
  return out;
}

export function compilePiiTemplate(file: PiiTemplateFile | null, errors: string[] = []): CompiledPiiTemplate {
  const out: CompiledPiiTemplate = {
    source: file ? "file" : "default",
    packs: [],
    detectors: [],
    labels: new Map(),
    fixtureDomains: (file?.fixtures?.domains ?? []).map((domain) => domain.toLowerCase()),
    fixturePaths: file?.fixtures?.paths ?? [],
    keep: compileKeep(file?.keep, errors),
    ignore: new Set((file?.ignore ?? []).map(normalizeLabel)),
    errors,
  };
  // why: a project's own pattern is the more specific claim, so it runs before the built-in shapes take its digits.
  compilePatterns(file?.patterns ?? [], errors, out);
  compilePacks(file?.extends ?? DEFAULT_PACKS, errors, out);
  compileFields(file?.fields ?? [], out);
  return out;
}

const cache = new Map<string, CompiledPiiTemplate>();

/**
 * why cached by content: every tool event reads the template, and a hook process is short-lived — compiling once per
 * distinct file text keeps a long session from re-parsing the same JSON on every read.
 */
export function loadPiiTemplate(root: string): CompiledPiiTemplate {
  let text: string | null = null;
  try {
    text = readFileSync(piiTemplatePath(root), "utf8");
  } catch {}
  const key = text ?? "";
  const cached = cache.get(key);
  if (cached) {
    return cached;
  }
  const errors: string[] = [];
  let file: PiiTemplateFile | null = null;
  if (text !== null) {
    try {
      file = JSON.parse(text) as PiiTemplateFile;
    } catch (error) {
      errors.push(`pii.json is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  const compiled = compilePiiTemplate(file, errors);
  cache.set(key, compiled);
  return compiled;
}

export type TemplateContext = { command?: string | undefined; filePath?: string | undefined };

// why: `cd ../other-project && curl …` reads the other project's data, so the directory a command moves into is
// where the rows it prints are described.
function cdTarget(command: string, base: string): string | null {
  let dir = base;
  let moved = false;
  for (const segment of tokenizeShell(command)) {
    const [verb, target] = segment.words;
    if (
      (verb?.text === "cd" || verb?.text === "pushd") &&
      target &&
      !target.unresolved &&
      target.text !== ""
    ) {
      dir = resolve(dir, target.text);
      moved = true;
    }
  }
  return moved ? dir : null;
}

const MAX_ANCESTORS = 32;

function nearestTemplateRoot(start: string): string | null {
  let dir = start;
  for (let depth = 0; depth < MAX_ANCESTORS; depth += 1) {
    if (existsSync(piiTemplatePath(dir))) {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      return null;
    }
    dir = parent;
  }
  return null;
}

/** The other projects whose templates describe what this event read, nearest template first. */
export function otherTemplateRoots(projectDir: string, context: TemplateContext): string[] {
  const starts = [
    context.command ? cdTarget(context.command, projectDir) : null,
    context.filePath ? dirname(resolve(projectDir, context.filePath)) : null,
  ];
  const roots = new Set<string>();
  for (const start of starts) {
    const root = start === null ? null : nearestTemplateRoot(start);
    if (root !== null && resolve(root) !== resolve(projectDir)) {
      roots.add(root);
    }
  }
  return [...roots];
}

function intersect<T>(a: Iterable<T>, b: Iterable<T>): T[] {
  const other = new Set(b);
  return [...a].filter((item) => other.has(item));
}

/**
 * Two templates combined so that neither loosens the other.
 *
 * invariant: what masks is the union and what exempts is the intersection. A template the session's project does
 * not own — one an agent could have written into a directory it then moved into — can only add protection: its
 * labels and patterns count, its fixtures, `keep` and `ignore` count only where the session's template agrees, and
 * `mask` beats `pseudonym` on a label both name.
 */
export function stricterOf(a: CompiledPiiTemplate, b: CompiledPiiTemplate): CompiledPiiTemplate {
  const labels = new Map(a.labels);
  for (const [name, rule] of b.labels) {
    const mine = labels.get(name);
    labels.set(name, mine === undefined || rule.mode === "mask" ? rule : mine);
  }
  const seen = new Set(a.detectors.map((detector) => `${detector.kind}\u0000${detector.regex.source}`));
  const detectors = [
    ...a.detectors,
    ...b.detectors.filter((detector) => !seen.has(`${detector.kind}\u0000${detector.regex.source}`)),
  ];
  return {
    source: a.source === "file" || b.source === "file" ? "file" : "default",
    packs: [...new Set([...a.packs, ...b.packs])],
    detectors,
    labels,
    fixtureDomains: intersect(a.fixtureDomains, b.fixtureDomains),
    fixturePaths: intersect(a.fixturePaths, b.fixturePaths),
    keep: new Set(intersect(a.keep, b.keep)),
    ignore: new Set(intersect(a.ignore, b.ignore)),
    errors: [...a.errors, ...b.errors],
  };
}

/** The template for one event: the session project's, made stricter by any other project the event read from. */
export function loadPiiTemplateFor(projectDir: string, context: TemplateContext): CompiledPiiTemplate {
  return otherTemplateRoots(projectDir, context)
    .map((root) => loadPiiTemplate(root))
    .reduce(stricterOf, loadPiiTemplate(projectDir));
}
