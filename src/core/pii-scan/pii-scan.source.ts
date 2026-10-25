import { extname } from "node:path";
import { tokenizeShell } from "../floor/floor.tokenize.ts";
import { LOG_COMMANDS, LOG_READERS } from "../secret-scan/secret-scan.cause.ts";

/**
 * Where an output's personal data came from, which decides the advice — the mask is the same everywhere.
 *
 * invariant: a client run locally and the same client run on a server are one source. `docker compose exec db psql`
 * and `kubectl exec pod -- psql` return the same rows a production psql would, so nothing here asks where the
 * database lives.
 */
export type PiiSource =
  | "db-query"
  | "api-response"
  | "log"
  | "data-file"
  | "source-file"
  | "config-file"
  | "other";

export type PiiSourceInput = {
  command?: string | undefined;
  toolName?: string | undefined;
  filePath?: string | undefined;
};

const DB_CLIENTS = new Set([
  "psql",
  "pgcli",
  "mysql",
  "mariadb",
  "mycli",
  "mongosh",
  "mongo",
  "sqlite3",
  "redis-cli",
  "cqlsh",
  "sqlcmd",
  "clickhouse-client",
  "duckdb",
  "litecli",
  "usql",
  "bq",
  "snowsql",
]);
const API_CLIENTS = new Set(["curl", "wget", "http", "https", "httpie", "xh", "grpcurl"]);
// why: a cloud CLI's data-plane subcommands return records the way a database client does.
const CLOUD_DATA =
  /(^|\s)(aws|awslocal)\s+(dynamodb|rds-data|athena)\b|(^|\s)gcloud\s+(firestore|spanner|sql)\b|(^|\s)az\s+cosmosdb\b/;
const MCP_DATABASE =
  /postgres|sql|mongo|redis|dynamo|database|supabase|bigquery|snowflake|clickhouse|firestore|neon|planetscale/i;

const CONFIG_EXTENSIONS = new Set([
  ".yaml",
  ".yml",
  ".json",
  ".toml",
  ".ini",
  ".properties",
  ".xml",
  ".conf",
  ".env",
]);
const DATA_EXTENSIONS = new Set([".csv", ".tsv", ".sql", ".jsonl", ".ndjson", ".dump"]);
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
  ".tf",
  ".vue",
  ".svelte",
  ".md",
]);

// why: every word of every segment, split again on spaces, so `ssh host 'psql -c …'` and `docker compose exec db
// mysql` expose the client as surely as running it directly does.
function wordsOf(command: string): string[] {
  return tokenizeShell(command).flatMap((segment) =>
    segment.words.flatMap((word) => word.text.split(/\s+/)).map((word) => word.split("/").pop() ?? word),
  );
}

function commandSource(command: string): PiiSource | null {
  const words = wordsOf(command);
  if (words.some((word) => DB_CLIENTS.has(word)) || CLOUD_DATA.test(command)) {
    return "db-query";
  }
  if (words.some((word) => API_CLIENTS.has(word))) {
    return "api-response";
  }
  if (LOG_READERS.test(command) || LOG_COMMANDS.test(command)) {
    return "log";
  }
  // why: `cat users.csv` or `head config.yaml` read a file through the shell, so the file decides the source.
  const named = words
    .map((word) => fileSource(word))
    .find((source) => source !== "other" && source !== "source-file");
  return named ?? null;
}

function fileSource(filePath: string): PiiSource {
  const extension = extname(filePath).toLowerCase();
  if (extension === ".log" || /(^|[/\\])logs?[/\\]/.test(filePath)) {
    return "log";
  }
  if (DATA_EXTENSIONS.has(extension)) {
    return "data-file";
  }
  if (CONFIG_EXTENSIONS.has(extension) || /(^|[/\\])\.env/.test(filePath)) {
    return "config-file";
  }
  return SOURCE_EXTENSIONS.has(extension) ? "source-file" : "other";
}

export function classifyPiiSource(input: PiiSourceInput): PiiSource {
  if (input.command) {
    return commandSource(input.command) ?? "other";
  }
  // why: an MCP tool is named `mcp__server__tool` on one host and `server_tool` on another; with no file behind it,
  // its output is a service's answer.
  const tool = input.toolName ?? "";
  if (tool.startsWith("mcp__") || (!input.filePath && tool.includes("_"))) {
    return MCP_DATABASE.test(tool) ? "db-query" : "api-response";
  }
  return input.filePath ? fileSource(input.filePath) : "other";
}
