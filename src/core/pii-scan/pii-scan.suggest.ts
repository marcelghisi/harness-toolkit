import { basename, extname } from "node:path";
import { DEFAULT_PACKS, PACKS, type PiiMode } from "./pii-scan.packs.ts";
import { normalizeLabel } from "./pii-scan.template.ts";

export type SchemaFile = { path: string; text: string };

export type SuggestedField = string | { name: string; kind?: string; mode?: PiiMode };

/**
 * A field someone who read the code judged personal — the `harness-pii` skill passes these, from domain classes in
 * languages no pattern here reads.
 */
export type PiiCandidate = { name: string; kind?: string; mode?: PiiMode; evidence?: string };

export type PiiSuggestion = {
  template: { extends: string[]; fields: SuggestedField[]; fixtures: { domains: string[]; paths: string[] } };
  /** why: each proposal names where it was seen, so the operator can judge it instead of trusting it. */
  evidence: { name: string; via: string; files: string[] }[];
};

const VENDORED = /(^|\/)(node_modules|vendor|dist|build|target|\.git|\.venv|venv|__pycache__)\//;

// why: the files where a project spells out the shape of its records — and only those, so a suggestion reads the
// schema, never the data.
export function isSchemaFile(path: string): boolean {
  const name = basename(path).toLowerCase();
  const extension = extname(name);
  if (VENDORED.test(path)) {
    return false;
  }
  const lower = path.toLowerCase();
  return (
    extension === ".sql" ||
    extension === ".prisma" ||
    extension === ".graphql" ||
    extension === ".gql" ||
    extension === ".proto" ||
    extension === ".avsc" ||
    /^(openapi|swagger)[\w.-]*\.(ya?ml|json)$/.test(name) ||
    /^(template|serverless)\.ya?ml$/.test(name) ||
    /changelog[\w.-]*\.(xml|ya?ml|json)$/.test(name) ||
    /^schema\.rb$/.test(name) ||
    /(schema|model|entity|types?|dto)s?\.([mc]?[jt]s|py)$/.test(name) ||
    /(^|\/)(migrations?|migrate|models?|entities|entity|schemas?|domain|dto)\//.test(lower)
  );
}

const SOURCE_EXTENSIONS = new Set([
  ".java",
  ".kt",
  ".kts",
  ".scala",
  ".cs",
  ".go",
  ".py",
  ".rb",
  ".php",
  ".ex",
  ".exs",
  ".ts",
  ".mts",
  ".cts",
  ".js",
  ".mjs",
  ".cjs",
]);

// invariant: a fixture, a seed or a dump is data, and a suggestion reads the schema, never the data.
const DATA_DIRECTORY =
  /(^|\/)(fixtures?|seeds?|seeders|dumps?|data|testdata|__test__|__tests__|tests?|spec)\//i;

/** A source file worth opening: a language an ORM or a schema library is written in, outside data and vendored code. */
export function isSchemaCandidate(path: string): boolean {
  if (VENDORED.test(path) || DATA_DIRECTORY.test(path)) {
    return false;
  }
  return isSchemaFile(path) || SOURCE_EXTENSIONS.has(extname(path).toLowerCase());
}

/**
 * hazard: a pattern written for one language reads noise in another — a Kotlin `val` in a TypeScript file, a Java
 * field in a Go one — so each dialect is chosen by extension, and a source file that is not named as a schema has
 * to carry its ORM's marker before any of its patterns run.
 */
type Dialect = { name: string; extensions: RegExp; marker: RegExp | null; patterns: readonly RegExp[] };

const DIALECTS: readonly Dialect[] = [
  {
    name: "sql",
    extensions: /\.(sql|[mc]?[jt]s|py|rb|go|java|kt)$/i,
    // why: a migration runner keeps its DDL in a string as often as in a .sql file.
    marker: /\bcreate\s+table\b|\balter\s+table\b/i,
    patterns: [
      /^\s*["`[]?([A-Za-z_]\w*)["`\]]?\s+(?:varchar|nvarchar|char|text|int|integer|bigint|smallint|uuid|date|datetime|timestamp|timestamptz|boolean|bool|numeric|decimal|json|jsonb|citext|float|double|real|serial|bigserial|blob|bytea|inet)\b/gim,
      /\badd\s+(?:column\s+)?["`]?([A-Za-z_]\w*)["`]?\s+[a-z]/gi,
    ],
  },
  {
    name: "prisma",
    extensions: /\.prisma$/i,
    marker: null,
    patterns: [/^\s*([a-z]\w*)\s+[A-Z]\w*[?[\]]*\s*(?:@|$)/gm],
  },
  {
    name: "jvm",
    extensions: /\.(java|kt|kts|scala)$/i,
    marker:
      /@(?:Entity|Table|Document|Embeddable|MappedSuperclass|Column|Id|Field|JsonProperty)\b|\bdata\s+class\b|\brecord\s+\w+\s*\(|\bcase\s+class\b/,
    patterns: [
      /@(?:Column|JoinColumn|Field|JsonProperty)\s*\([^)]*?\b(?:name\s*=\s*|value\s*=\s*)?"([A-Za-z_]\w*)"/g,
      /^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:private|protected|public)\s+(?:final\s+|transient\s+)*[\w.]+(?:<[^;=()]*>)?(?:\[\])?\s+([a-z]\w*)\s*(?:=[^;]*)?;/gm,
      /\b(?:val|var)\s+([a-z]\w*)\s*:/g,
      /\brecord\s+\w+\s*\(([^)]*)\)/g,
    ],
  },
  {
    name: "csharp",
    extensions: /\.cs$/i,
    marker: /\{\s*get;|\bDbSet<|\[Table\(|\bDbContext\b|table\.Column</,
    patterns: [
      /\bpublic\s+(?:virtual\s+|required\s+|override\s+)*[\w.<>?,[\] ]+?\s+([A-Z]\w*)\s*\{\s*get;/g,
      /\[(?:Column|JsonPropertyName)\(\s*"([A-Za-z_]\w*)"/g,
      /\b([A-Z]\w*)\s*=\s*table\.Column</g,
    ],
  },
  {
    name: "go",
    extensions: /\.go$/i,
    marker: /`[^`]*\b(?:json|gorm|db|bson):"/,
    patterns: [
      /\b(?:json|db|bson|yaml|xml):"([A-Za-z_]\w*)/g,
      /\bcolumn:([A-Za-z_]\w*)/g,
      /^\s+([A-Z]\w*)\s+[\w.*[\]]+\s+`/gm,
    ],
  },
  {
    name: "python",
    extensions: /\.py$/i,
    marker:
      /\bmodels\.Model\b|\bdb\.Model\b|declarative_base|DeclarativeBase|mapped_column|\bColumn\(|\bBaseModel\b|@dataclass|\bTypedDict\b|\bop\.(?:create_table|add_column)|\bmigrations\.\w+|\bSQLModel\b/,
    patterns: [
      /^\s+([a-z_]\w*)\s*(?::\s*[^=\n]+)?=\s*(?:models\.\w+|db\.Column|sa\.Column|Column|mapped_column|Field|fields\.\w+)\(/gm,
      /^\s+([a-z_]\w*)\s*:\s*(?:Mapped\[)?[A-Za-z_][\w.[\], |]*\]?\s*(?:=.*)?$/gm,
      /\bColumn\(\s*["']([A-Za-z_]\w*)["']/g,
      /\(\s*["']([a-z_]\w*)["']\s*,\s*models\.\w+/g,
    ],
  },
  {
    name: "ruby",
    extensions: /\.rb$/i,
    marker: /\bcreate_table\b|\badd_column\b|ActiveRecord|\bschema\.define\b|\battribute\s+:/,
    patterns: [
      /\bt\.\w+\s+[:"']([a-z_]\w*)/g,
      /\badd_column\s+:\w+\s*,\s*:([a-z_]\w*)/g,
      /\battribute\s+:([a-z_]\w*)/g,
    ],
  },
  {
    name: "php",
    extensions: /\.php$/i,
    marker: /\bSchema::|\bBlueprint\b|ORM\\|@ORM\b|\$fillable\b|extends\s+Model\b/,
    patterns: [
      /\$table->\w+\(\s*['"]([A-Za-z_]\w*)['"]/g,
      /(?:private|protected|public)\s+\??[\w\\]*\s*\$([a-z]\w*)\s*[;=]/g,
    ],
  },
  {
    name: "elixir",
    extensions: /\.exs?$/i,
    marker: /\bEcto\.|\bschema\s+"|\bcreate\s+table\(/,
    patterns: [/\b(?:field|add)\s+:([a-z_]\w*)/g],
  },
  {
    name: "js-orm",
    extensions: /\.[mc]?[jt]s$/i,
    marker:
      /@Entity\b|@Column\b|@Prop\b|\bDataTypes\.|mongoose\.Schema|new\s+Schema\(|\b(?:pg|mysql|sqlite)Table\(|\bz\.object\(|\bcreateTable\(|\baddColumn\(|\bdefineModel\(|\bsequelize\.define\(/,
    patterns: [
      /@(?:Column|PrimaryColumn|Prop|Field|Property)\([^)]*\)\s*(?:(?:public|private|readonly)\s+)*([A-Za-z_]\w*)\s*[?!]?\s*:/g,
      /\b(?:table|t)\.\w+\(\s*['"]([A-Za-z_]\w*)['"]/g,
      /\b(?:text|varchar|char|integer|serial|timestamp|boolean|uuid|date|json|jsonb)\(\s*["']([A-Za-z_]\w*)["']/g,
      /\baddColumn\(\s*['"]\w+['"]\s*,\s*['"]([A-Za-z_]\w*)['"]/g,
    ],
  },
  {
    name: "protobuf",
    extensions: /\.proto$/i,
    marker: null,
    patterns: [/^\s*(?:optional\s+|repeated\s+|required\s+)?[\w.]+(?:<[^>]+>)?\s+([A-Za-z_]\w*)\s*=\s*\d+/gm],
  },
  {
    name: "avro",
    extensions: /\.avsc$/i,
    marker: null,
    patterns: [/"name"\s*:\s*"([A-Za-z_]\w*)"/g],
  },
  {
    name: "liquibase",
    extensions: /changelog[\w.-]*\.(xml|ya?ml|json)$/i,
    marker: null,
    patterns: [/<column\s+[^>]*\bname="([A-Za-z_]\w*)"/g, /\bname["']?\s*:\s*["']?([A-Za-z_]\w*)/g],
  },
];

// why: an object key, a TS/zod property, a YAML or OpenAPI property, a GraphQL field — the shape every named schema
// file shares, whatever wrote it.
const KEY_PATTERNS: readonly RegExp[] = [
  /^\s*["']?([A-Za-z_][\w]*)["']?\s*[?!]?\s*:/gm,
  // why: a key inside an inline object literal — `z.object({ email: z.string() })` puts no key at a line start.
  /[{,]\s*["']?([A-Za-z_][\w]*)["']?\s*\??\s*:/g,
];
const KEYED_FILE = /\.(ya?ml|json|graphql|gql|[mc]?[jt]s)$/i;

// why: a DynamoDB key or index attribute in CloudFormation or SAM.
const ATTRIBUTE_NAME = /AttributeName:\s*["']?([A-Za-z_]\w*)/g;

// why: an infrastructure template's keys configure resources (`EmailMessage`, `Condition`, `PolicyDocument`); only
// the attributes it declares for a table describe a record.
const INFRA_TEMPLATE = /(^|\/)(template|serverless)\.ya?ml$/i;

/** The patterns that read a file's field names — none when it is not a schema. */
export function schemaPatterns(path: string, text: string): RegExp[] {
  if (INFRA_TEMPLATE.test(path)) {
    return [ATTRIBUTE_NAME];
  }
  const named = isSchemaFile(path);
  const out: RegExp[] = [];
  for (const dialect of DIALECTS) {
    if (
      dialect.extensions.test(path) &&
      (dialect.marker === null ? named : named || dialect.marker.test(text))
    ) {
      out.push(...dialect.patterns);
    }
  }
  if (named && KEYED_FILE.test(path)) {
    out.push(...KEY_PATTERNS);
  }
  return out;
}

// why: a Java record and a Kotlin constructor list their components in one capture — `String fullName, String email`.
function componentsOf(captured: string): string[] {
  if (!/[,\s]/.test(captured.trim())) {
    return [captured];
  }
  return captured
    .split(",")
    .map((part) => /([A-Za-z_]\w*)\s*$/.exec(part.replace(/@\w+(\([^)]*\))?/g, "").trim())?.[1] ?? "")
    .filter(Boolean);
}

/**
 * The field names a schema file declares — in `scanned` only, with the dialect chosen from the whole file, so a
 * diff's added lines are read by the patterns their file's ORM marker selects.
 */
export function fieldsIn(path: string, text: string, scanned: string = text): Set<string> {
  const out = new Set<string>();
  for (const pattern of schemaPatterns(path, text)) {
    for (const match of scanned.matchAll(new RegExp(pattern.source, pattern.flags))) {
      for (const name of componentsOf(match[1] ?? "")) {
        out.add(normalizeLabel(name));
      }
    }
  }
  return out;
}

// why the last word only: `customer_email` holds a mailbox, `email_subject` and `email_template` configure one.
const PERSONAL_TOKENS =
  /(^|_)(email|mail|correo|phone|telefone|telefono|celular|mobile|address|endereco|direccion|adresse|cpf|cnpj|ssn|nif|dni|birth_date|birthdate|nascimento|nacimiento|passport|passaporte|zip|zip_code|postal_code|postcode|cep|login_ip|user_ip|signup_ip)$/;
// why: `name` alone is a project's, a tool's or a file's as often as a person's — it counts only beside a word for a
// person.
const PERSON_NAME =
  /(^|_)(first|last|full|given|family|middle|maiden|sur|customer|user|contact|holder|client|cliente|patient|paciente|employee|person|owner|titular|usuario)_?(name|nome|nombre|nom)$/;

// why: a locale folder or file names the languages the product speaks, which are the languages its field names and
// its users' data are likely to come in.
const LOCALE = /(^|[/._-])(pt|es|fr|de|it)([-_][A-Za-z]{2})?([/._]|$)/;

export function packsFor(field: string): string[] {
  return PACKS.filter((pack) => pack.id !== "global" && pack.labels && Object.hasOwn(pack.labels, field)).map(
    (pack) => pack.id,
  );
}

/** A field name that a pack labels or that ends in a word for personal data. */
export function looksPersonal(field: string): boolean {
  return packsFor(field).length > 0 || PERSONAL_TOKENS.test(field) || PERSON_NAME.test(field);
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

function candidateField(candidate: PiiCandidate, name: string): SuggestedField {
  if (candidate.kind === undefined && candidate.mode === undefined) {
    return name;
  }
  return {
    name,
    ...(candidate.kind ? { kind: candidate.kind } : {}),
    ...(candidate.mode ? { mode: candidate.mode } : {}),
  };
}

/**
 * A proposed `pii.json` for a project, read from its schema files and its locale folders, plus any candidates a
 * reader of the code proposed.
 *
 * invariant: a proposal, never a decision. It prints for the operator to review and save; nothing here writes the
 * template, because the template is policy and policy is the operator's.
 */
export function suggestPiiTemplate(
  files: readonly SchemaFile[],
  allPaths: readonly string[] = [],
  candidates: readonly PiiCandidate[] = [],
): PiiSuggestion {
  const seen = collectFields(files);
  const judged = new Map<string, PiiCandidate>();
  for (const candidate of candidates) {
    const name = normalizeLabel(candidate.name);
    if (name !== "") {
      judged.set(name, candidate);
      const where = seen.get(name) ?? new Set<string>();
      where.add(candidate.evidence ? `candidate: ${candidate.evidence}` : "candidate");
      seen.set(name, where);
    }
  }
  const packs = new Set<string>(["global"]);
  const fields: SuggestedField[] = [];
  const evidence: PiiSuggestion["evidence"] = [];
  for (const [field, where] of [...seen.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const fromPacks = packsFor(field);
    const files_ = [...where].sort().slice(0, 3);
    const candidate = judged.get(field);
    if (fromPacks.length > 0) {
      const chosen =
        fromPacks.find((id) => id.startsWith("id:") || id.startsWith("domain:")) ?? fromPacks[0] ?? "";
      packs.add(chosen);
      evidence.push({ name: field, via: chosen, files: files_ });
    } else if (candidate || PERSONAL_TOKENS.test(field) || PERSON_NAME.test(field)) {
      fields.push(candidate ? candidateField(candidate, field) : field);
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
