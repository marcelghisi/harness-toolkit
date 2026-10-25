import { basename, extname } from "node:path";
import { DEFAULT_PACKS, PACKS } from "./pii-scan.packs.ts";
import { normalizeLabel } from "./pii-scan.template.ts";

export type SchemaFile = { path: string; text: string };

export type PiiSuggestion = {
  template: { extends: string[]; fields: string[]; fixtures: { domains: string[]; paths: string[] } };
  /** why: each proposal names where it was seen, so the operator can judge it instead of trusting it. */
  evidence: { name: string; via: string; files: string[] }[];
};

// why: the files where a project spells out the shape of its records — and only those, so a suggestion reads the
// schema, never the data.
export function isSchemaFile(path: string): boolean {
  const name = basename(path).toLowerCase();
  const extension = extname(name);
  if (path.includes("node_modules/") || path.includes("/dist/")) {
    return false;
  }
  return (
    extension === ".sql" ||
    extension === ".prisma" ||
    extension === ".graphql" ||
    extension === ".gql" ||
    /^(openapi|swagger)[\w.-]*\.(ya?ml|json)$/.test(name) ||
    /^(template|serverless)\.ya?ml$/.test(name) ||
    /(schema|model|entity|types?|dto)s?\.(ts|js|py)$/.test(name) ||
    /(^|\/)(migrations?|models?|entities|schemas?)\//.test(path.toLowerCase())
  );
}

const FIELD_PATTERNS: readonly RegExp[] = [
  // why: an object key, a TS/zod property, a YAML or OpenAPI property, a GraphQL field.
  /^\s*["']?([A-Za-z_][\w]*)["']?\s*\??\s*:/gm,
  // why: a SQL column inside CREATE TABLE.
  /^\s*["`]?([A-Za-z_]\w*)["`]?\s+(?:varchar|char|text|int|integer|bigint|smallint|uuid|date|timestamp|timestamptz|boolean|bool|numeric|decimal|json|jsonb|citext|float|double|real|serial|bigserial)\b/gim,
  // why: a Prisma model field — lower-case name, then a type.
  /^\s*([a-z]\w*)\s+[A-Z]\w*[?[\]]*\s*(?:@|$)/gm,
  // why: a key inside an inline object literal — `z.object({ email: z.string() })` puts no key at a line start.
  /[{,]\s*["']?([A-Za-z_][\w]*)["']?\s*\??\s*:/g,
  // invariant: last, because an infrastructure template is read with this pattern alone.
  // why: a DynamoDB key or index attribute in CloudFormation or SAM.
  /AttributeName:\s*["']?([A-Za-z_]\w*)/g,
];

// why the last word only: `customer_email` holds a mailbox, `email_subject` and `email_template` configure one.
const PERSONAL_TOKENS =
  /(^|_)(email|mail|correo|phone|telefone|telefono|celular|mobile|address|endereco|direccion|adresse|cpf|cnpj|ssn|nif|dni|birth_date|birthdate|nascimento|nacimiento|passport|passaporte)$/;
// why: `name` alone is a project's, a tool's or a file's as often as a person's — it counts only beside a word for a
// person.
const PERSON_NAME =
  /(^|_)(first|last|full|given|family|middle|maiden|sur|customer|user|contact|holder|client|cliente|patient|paciente|employee|person|owner|titular|usuario)_?(name|nome|nombre|nom)$/;

// why: a locale folder or file names the languages the product speaks, which are the languages its field names and
// its users' data are likely to come in.
const LOCALE = /(^|[/._-])(pt|es|fr|de|it)([-_][A-Za-z]{2})?([/._]|$)/;

// why: an infrastructure template's keys configure resources (`EmailMessage`, `Condition`, `PolicyDocument`); only
// the attributes it declares for a table describe a record.
const INFRA_TEMPLATE = /(^|\/)(template|serverless)\.ya?ml$/i;

function fieldsIn(path: string, text: string): Set<string> {
  const out = new Set<string>();
  const patterns = INFRA_TEMPLATE.test(path) ? FIELD_PATTERNS.slice(-1) : FIELD_PATTERNS;
  for (const pattern of patterns) {
    for (const match of text.matchAll(new RegExp(pattern.source, pattern.flags))) {
      if (match[1]) {
        out.add(normalizeLabel(match[1]));
      }
    }
  }
  return out;
}

function packsFor(field: string): string[] {
  return PACKS.filter((pack) => pack.id !== "global" && pack.labels && Object.hasOwn(pack.labels, field)).map(
    (pack) => pack.id,
  );
}

function localePacks(paths: readonly string[]): string[] {
  const packs = new Set<string>();
  for (const path of paths) {
    if (!/locale|i18n|lang|messages|translations/i.test(path)) {
      continue;
    }
    const match = LOCALE.exec(path.toLowerCase());
    if (match?.[2]) {
      packs.add(`lang:${match[2]}`);
    }
  }
  return [...packs];
}

type Seen = Map<string, Set<string>>;

function collectFields(files: readonly SchemaFile[]): Seen {
  const seen: Seen = new Map();
  for (const file of files) {
    for (const field of fieldsIn(file.path, file.text)) {
      const where = seen.get(field) ?? new Set<string>();
      where.add(file.path);
      seen.set(field, where);
    }
  }
  return seen;
}

/**
 * A proposed `pii.json` for a project, read from its schema files and its locale folders.
 *
 * invariant: a proposal, never a decision. It prints for the operator to review and save; nothing here writes the
 * template, because the template is policy and policy is the operator's.
 */
export function suggestPiiTemplate(
  files: readonly SchemaFile[],
  allPaths: readonly string[] = [],
): PiiSuggestion {
  const seen = collectFields(files);
  const packs = new Set<string>(["global"]);
  const fields: string[] = [];
  const evidence: PiiSuggestion["evidence"] = [];
  for (const [field, where] of [...seen.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const fromPacks = packsFor(field);
    const files_ = [...where].sort().slice(0, 3);
    if (fromPacks.length > 0) {
      const chosen =
        fromPacks.find((id) => id.startsWith("id:") || id.startsWith("domain:")) ?? fromPacks[0] ?? "";
      packs.add(chosen);
      evidence.push({ name: field, via: chosen, files: files_ });
    } else if (PERSONAL_TOKENS.test(field) || PERSON_NAME.test(field)) {
      fields.push(field);
      evidence.push({ name: field, via: "fields", files: files_ });
    }
  }
  for (const pack of localePacks(allPaths)) {
    packs.add(pack);
    evidence.push({ name: pack, via: "locale files", files: [] });
  }
  // why: the checksummed defaults cost nothing to keep, and a project that serves one country still receives mail
  // from people in others.
  for (const pack of DEFAULT_PACKS) {
    if (pack.startsWith("id:")) {
      packs.add(pack);
    }
  }
  return {
    template: { extends: [...packs], fields, fixtures: { domains: [], paths: [] } },
    evidence,
  };
}
