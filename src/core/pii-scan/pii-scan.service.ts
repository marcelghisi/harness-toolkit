import type { PiiMode } from "./pii-scan.packs.ts";
import { type CompiledPiiTemplate, type LabelRule, normalizeLabel } from "./pii-scan.template.ts";

export type PiiMatch = { start: number; end: number; kind: string; mode: PiiMode };

type Span = { start: number; end: number };

/**
 * invariant: reserved for documentation and testing by RFC 2606 and RFC 6761, so an address under one is a fixture
 * by definition and never someone's mailbox.
 */
const RESERVED_DOMAIN = /(^|\.)(example\.(com|net|org)|example|invalid|test|localhost|local)$/i;

// why: role and automation mailboxes name a function, not a person, and masking them only hides who to contact.
const ROLE_LOCAL_PART =
  /^(no-?reply|do-?not-?reply|support|info|admin|contact|hello|security|privacy|team|dev|bot|notifications?|postmaster|abuse|webmaster|sales|billing|help)$/i;
const NOREPLY_DOMAIN = /(^|\.)users\.noreply\.github\.com$/i;

// why: the issuers' published test numbers are what a fixture is supposed to use, so they stay readable.
const TEST_CARDS = new Set([
  "4242424242424242",
  "4111111111111111",
  "4000056655665556",
  "4012888888881881",
  "5555555555554444",
  "5105105105105100",
  "2223003122003222",
  "378282246310005",
  "371449635398431",
  "6011111111111117",
  "3566002020360505",
]);

// why: what a careful system already prints in place of a value — masking it again only adds noise.
const PLACEHOLDER = /^(?:\[(?:REDACTED|PII)[^\]]*\]|\*+|<[^>]*>|\$\{[^}]*\}|null|none|undefined|n\/a|-|)$/i;

function isFixtureEmail(value: string, template: CompiledPiiTemplate): boolean {
  const at = value.lastIndexOf("@");
  if (at === -1) {
    return false;
  }
  const local = value.slice(0, at);
  const domain = value.slice(at + 1).toLowerCase();
  return (
    RESERVED_DOMAIN.test(domain) ||
    NOREPLY_DOMAIN.test(domain) ||
    ROLE_LOCAL_PART.test(local) ||
    template.fixtureDomains.some((fixture) => domain === fixture || domain.endsWith(`.${fixture}`))
  );
}

// why: a field's value in code is an expression or a type — `email: user.email`, `name: string` — and masking it
// would hand the agent a file it can no longer edit.
const CODE_VALUE =
  /^(?:[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)+|.*[()=>{}].*|string|number|boolean|bigint|any|unknown|never|Date|String|Number|Boolean|true|false)$/;

function isFixtureValue(kind: string, value: string, template: CompiledPiiTemplate): boolean {
  const trimmed = value.trim();
  if (PLACEHOLDER.test(trimmed) || CODE_VALUE.test(trimmed)) {
    return true;
  }
  if (trimmed.includes("@") && isFixtureEmail(trimmed, template)) {
    return true;
  }
  return kind === "card" && TEST_CARDS.has(trimmed.replace(/\D/g, ""));
}

/**
 * why a curated suffix list: `customer_email` and `billing_phone` are personal by their last word, but `file_name`,
 * `host_name` and `mac_address` are not — so `name` and `address` match only exactly, never as a suffix.
 */
const PERSONAL_SUFFIXES = new Set([
  "email",
  "e_mail",
  "phone",
  "phone_number",
  "mobile",
  "cpf",
  "cnpj",
  "ssn",
  "dob",
  "birth_date",
  "date_of_birth",
  "first_name",
  "last_name",
  "full_name",
  "telefone",
  "celular",
  "nome_completo",
]);

function labelFor(name: string, template: CompiledPiiTemplate): LabelRule | undefined {
  const key = normalizeLabel(name);
  const exact = template.labels.get(key);
  if (exact) {
    return exact;
  }
  const tokens = key.split("_");
  for (let take = Math.min(3, tokens.length - 1); take >= 1; take -= 1) {
    const suffix = tokens.slice(-take).join("_");
    const rule = PERSONAL_SUFFIXES.has(suffix) ? template.labels.get(suffix) : undefined;
    if (rule) {
      return rule;
    }
  }
  return undefined;
}

// why: a JSON key and its string or number value — the shape every API response and document store returns.
const JSON_FIELD = /"([^"\\\n]{1,64})"\s*:\s*(?:"((?:[^"\\\n]|\\.)*)"|(-?\d[\d.]*))/g;
// why: `key=value` stops at whitespace, as a log line writes it; `key: value` runs to the end of the clause, as YAML
// and human-readable logs write a name with a space in it.
const EQUALS_FIELD = /(?<![\w"'])([A-Za-z_][\w.-]{0,63})\s*=\s*(?:"([^"\n]*)"|'([^'\n]*)'|([^\s"',;&|}]+))/g;
const COLON_FIELD = /(?<![\w"'/])([A-Za-z_][\w.-]{0,63}):[ \t]*(?:"([^"\n]*)"|'([^'\n]*)'|([^\n"',;&|}]+))/g;

function labelledFieldMatches(text: string, template: CompiledPiiTemplate): PiiMatch[] {
  const out: PiiMatch[] = [];
  const push = (rule: LabelRule, value: string, start: number): void => {
    if (value.trim() !== "" && !isFixtureValue(rule.kind, value, template)) {
      out.push({ start, end: start + value.length, kind: rule.kind, mode: rule.mode });
    }
  };
  for (const match of text.matchAll(JSON_FIELD)) {
    const rule = labelFor(match[1] ?? "", template);
    const value = match[2] ?? match[3];
    if (rule && value !== undefined && match.index !== undefined) {
      push(rule, value, match.index + match[0].lastIndexOf(value));
    }
  }
  for (const match of [...text.matchAll(EQUALS_FIELD), ...text.matchAll(COLON_FIELD)]) {
    const rule = labelFor(match[1] ?? "", template);
    const value = (match[2] ?? match[3] ?? match[4] ?? "").trimEnd();
    if (rule && match.index !== undefined) {
      push(rule, value, match.index + match[0].lastIndexOf(value));
    }
  }
  return out;
}

type Line = { text: string; start: number };

function linesOf(text: string): Line[] {
  const out: Line[] = [];
  let start = 0;
  for (const text_ of text.split("\n")) {
    out.push({ text: text_, start });
    start += text_.length + 1;
  }
  return out;
}

type Cell = { text: string; start: number; end: number };

function splitCells(line: Line, delimiter: string, outerPipes: boolean): Cell[] {
  const cells: Cell[] = [];
  let from = 0;
  let quoted = false;
  for (let index = 0; index <= line.text.length; index += 1) {
    const char = line.text[index];
    if (char === '"' && delimiter === ",") {
      quoted = !quoted;
    }
    if (index === line.text.length || (char === delimiter && !quoted)) {
      const raw = line.text.slice(from, index);
      const lead = raw.length - raw.trimStart().length;
      const value = raw.trim().replace(/^"(.*)"$/, "$1");
      const offset = raw.trim().startsWith('"') ? 1 : 0;
      cells.push({
        text: value,
        start: line.start + from + lead + offset,
        end: line.start + from + lead + offset + value.length,
      });
      from = index + 1;
    }
  }
  return outerPipes ? cells.slice(1, -1) : cells;
}

const BORDER = /^\s*\+[-+]+\+\s*$/;
const RULE = /^\s*-+(\+-+)*\s*$/;
const IDENTIFIER = /^[A-Za-z_][\w .-]{0,63}$/;

type Table = { header: Cell[]; rows: Cell[][] };

const SPACED_RULE = /^\s*-+(?: +-+)+\s*$/;

// why: sqlite `-column`, `psql` with an unaligned border off, and most CLI table printers align columns with spaces
// and rule a dashed line beneath — the dash groups are the only record of where one column ends.
function columnsOf(rule: Line): Span[] {
  return [...rule.text.matchAll(/-+/g)].map((match) => ({
    start: match.index ?? 0,
    end: (match.index ?? 0) + match[0].length,
  }));
}

function sliceColumns(line: Line, columns: readonly Span[]): Cell[] {
  return columns.map((column, index) => {
    const end =
      index + 1 < columns.length ? (columns[index + 1]?.start ?? line.text.length) : line.text.length;
    const raw = line.text.slice(column.start, end);
    const lead = raw.length - raw.trimStart().length;
    const text = raw.trim();
    return {
      text,
      start: line.start + column.start + lead,
      end: line.start + column.start + lead + text.length,
    };
  });
}

function spacedTableAt(lines: readonly Line[], index: number): { table: Table; next: number } | null {
  const line = lines[index];
  const rule = lines[index + 1];
  if (!line || !rule || !SPACED_RULE.test(rule.text) || /[|,\t]/.test(line.text)) {
    return null;
  }
  const columns = columnsOf(rule);
  const header = sliceColumns(line, columns);
  if (!header.every((cell) => IDENTIFIER.test(cell.text))) {
    return null;
  }
  const rows: Cell[][] = [];
  let cursor = index + 2;
  for (; cursor < lines.length && (lines[cursor]?.text.trim() ?? "") !== ""; cursor += 1) {
    const row = lines[cursor];
    if (row) {
      rows.push(sliceColumns(row, columns));
    }
  }
  return rows.length > 0 ? { table: { header, rows }, next: cursor } : null;
}

function tableAt(lines: readonly Line[], index: number): { table: Table; next: number } | null {
  const line = lines[index];
  const after = lines[index + 1];
  if (!line || !after) {
    return null;
  }
  const spaced = spacedTableAt(lines, index);
  if (spaced) {
    return spaced;
  }
  // why: mysql frames its header between `+---+` borders and pipes every row on both sides; psql rules a dashed
  // line under an unframed header; sqlite `-header` and CSV just put the names on the first line.
  const framed =
    BORDER.test(line.text) && lines[index + 2] !== undefined && BORDER.test(lines[index + 2]?.text ?? "");
  const headerLine = framed ? after : line;
  const delimiter = headerLine.text.includes("|") ? "|" : headerLine.text.includes("\t") ? "\t" : ",";
  const outerPipes = framed || /^\s*\|.*\|\s*$/.test(headerLine.text);
  const header = splitCells(headerLine, delimiter, outerPipes);
  if (header.length < 2 || !header.every((cell) => IDENTIFIER.test(cell.text))) {
    return null;
  }
  const ruled = !framed && RULE.test(after.text);
  let cursor = framed ? index + 3 : ruled ? index + 2 : index + 1;
  const rows: Cell[][] = [];
  for (; cursor < lines.length; cursor += 1) {
    const row = lines[cursor];
    if (!row || row.text.trim() === "") {
      break;
    }
    if (BORDER.test(row.text)) {
      continue;
    }
    const cells = splitCells(row, delimiter, outerPipes);
    if (cells.length !== header.length) {
      break;
    }
    rows.push(cells);
  }
  return rows.length > 0 ? { table: { header, rows }, next: cursor } : null;
}

function tableMatches(text: string, template: CompiledPiiTemplate): PiiMatch[] {
  const out: PiiMatch[] = [];
  const lines = linesOf(text);
  let index = 0;
  while (index < lines.length) {
    const found = tableAt(lines, index);
    if (!found) {
      index += 1;
      continue;
    }
    const rules = found.table.header.map((cell) => labelFor(cell.text, template));
    for (const row of found.table.rows) {
      row.forEach((cell, column) => {
        const rule = rules[column];
        if (rule && cell.text !== "" && !isFixtureValue(rule.kind, cell.text, template)) {
          out.push({ start: cell.start, end: cell.end, kind: rule.kind, mode: rule.mode });
        }
      });
    }
    index = found.next;
  }
  return out;
}

function overlaps(a: Span, b: Span): boolean {
  return a.start < b.end && b.start < a.end;
}

function valueMatches(text: string, template: CompiledPiiTemplate, taken: readonly Span[]): PiiMatch[] {
  const out: PiiMatch[] = [];
  for (const detector of template.detectors) {
    for (const match of text.matchAll(new RegExp(detector.regex.source, detector.regex.flags))) {
      if (match.index === undefined) {
        continue;
      }
      const span = { start: match.index, end: match.index + match[0].length };
      if ([...taken, ...out].some((other) => overlaps(span, other))) {
        continue;
      }
      if (detector.validate && !detector.validate(match[0])) {
        continue;
      }
      if (!isFixtureValue(detector.kind, match[0], template)) {
        out.push({ ...span, kind: detector.kind, mode: detector.mode });
      }
    }
  }
  return out;
}

/**
 * The personal data in a piece of text, by the project's own definition of it.
 *
 * invariant: pure — no I/O. The template is compiled by the caller, so the same text under the same template always
 * yields the same spans, and `taken` keeps the spans a secret mask already claimed.
 */
export type PiiScanOptions = {
  /**
   * why off for source files: a field name in code labels a variable, not a value — only a literal shaped like a
   * document, a card or a mailbox is personal data there.
   */
  fields?: boolean;
  taken?: readonly Span[];
};

export function scanForPii(
  text: string | undefined,
  template: CompiledPiiTemplate,
  options: PiiScanOptions = {},
): PiiMatch[] {
  if (!text) {
    return [];
  }
  // why: a token this harness already wrote carries a domain or a country, and scanning it again would mask the
  // attribute that was left visible on purpose.
  const tokens = [...text.matchAll(/\[(?:PII|REDACTED)[^\]\n]*\]/g)].map((match) => ({
    start: match.index ?? 0,
    end: (match.index ?? 0) + match[0].length,
  }));
  const taken = [...(options.taken ?? []), ...tokens];
  const fielded =
    options.fields === false
      ? []
      : [...tableMatches(text, template), ...labelledFieldMatches(text, template)];
  const labelled: PiiMatch[] = [];
  for (const match of fielded) {
    if (![...taken, ...labelled].some((other) => overlaps(match, other))) {
      labelled.push(match);
    }
  }
  const values = valueMatches(text, template, [...taken, ...labelled]);
  return [...labelled, ...values].sort((a, b) => a.start - b.start);
}
