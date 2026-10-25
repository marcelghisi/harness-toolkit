import type { HarnessEventKind } from "../../contracts/harness-event.ts";
import { scanForPii } from "../pii-scan/pii-scan.service.ts";
import type { CompiledPiiTemplate } from "../pii-scan/pii-scan.template.ts";
import type { KnownSecret } from "../secret-scan/secret-scan.known.ts";
import { scanForSecrets } from "../secret-scan/secret-scan.service.ts";

export type ObsLevel = "signal" | "debug";

export type ObsKind =
  | "session.start"
  | "session.end"
  | "generation.start"
  | "generation.end"
  | "tool.start"
  | "tool.end"
  | "tool.fail"
  | "shell.start"
  | "shell.end"
  | "mcp.start"
  | "mcp.end"
  | "subagent.start"
  | "subagent.end"
  | "file.edit"
  | "file.read"
  | "prompt.submit"
  | "agent.response"
  | "agent.thought"
  | "compact"
  | "gate.outcome"
  | "cost.turn"
  | "cost.session_alert"
  | "ship.claim"
  | "policy.deny"
  // why: an observation is not a refusal. Sharing the kind would inflate the denial count with readings the
  // operator never lived through, which is the opposite of what the rail exists for.
  | "policy.observe"
  // why: a masked secret is a defect in the code that produced it, so it is counted where the operator looks — by
  // cause, with the variable names and never the values ([/decisions/ad-149.md](/decisions/ad-149.md)).
  | "secret.masked"
  // why: personal data is counted by where it surfaced — a query result is expected, a log or a source file is a
  // defect — with kinds and subjects and never a value ([/decisions/ad-151.md](/decisions/ad-151.md)).
  | "pii.masked"
  | "pii.written"
  // why: turning the protection off is an operator decision, and one an auditor should be able to see was made.
  | "pii.disabled";

export type CostPool = "provider_native" | "other" | "auto" | "unknown";

export type CostSource = "provider" | "litellm" | "override" | "billed" | "missing";

export type ObsEvent = {
  schema: "harness.observability.v1";
  provider: string;
  kind: ObsKind;
  level: ObsLevel;
  ts: string;
  trace_id: string;
  span_id: string;
  parent_span_id?: string;
  session_id?: string;
  model?: string;
  attrs: Record<string, unknown>;
  // invariant: every field here is written by `usageGenAi`. `operation_name`, `provider_name`, `request_model`,
  // `reasoning_tokens` and `outcome` were declared on the shipped schema and populated by nothing, which is the
  // same defect as a consumer without a producer pointed the other way ([/decisions/ad-041.md](/decisions/ad-041.md)).
  gen_ai?: {
    input_tokens?: number;
    output_tokens?: number;
    cache_read_tokens?: number;
    cache_write_tokens?: number;
    cost_usd?: number | null;
    cost_source?: CostSource;
    cost_pool?: CostPool;
    duration_ms?: number;
  };
};

export type AuditRecord = {
  ts: string;
  event: string;
  payload: unknown;
};

export type ObservabilityConfig = {
  enabled: boolean;
  signalPath: "obs.jsonl";
  debugPath: "debug.jsonl";
  debugEnabled: boolean;
  includePayloads: boolean;
  maxAttrChars: number;
  sessionCostAlertUsd: number | null;
  retentionDays: number;
  maxSignalEvents: number;
  globalSpool: boolean;
  /** why: reading the hook's environment and `.env` is the operator's choice (`secrets.knownValues`), on disk too. */
  maskKnownValues?: boolean;
  /** why: a record on disk outlives the session, so personal data is masked there whenever the rail is on. */
  maskPii?: boolean;
};

export const DEFAULT_OBS: ObservabilityConfig = {
  enabled: true,
  signalPath: "obs.jsonl",
  debugPath: "debug.jsonl",
  debugEnabled: false,
  includePayloads: false,
  maxAttrChars: 500,
  sessionCostAlertUsd: 5,
  retentionDays: 14,
  maxSignalEvents: 50_000,
  globalSpool: false,
};

export const SIGNAL_KINDS = new Set<ObsKind>([
  "session.start",
  "session.end",
  "generation.end",
  "tool.fail",
  "subagent.start",
  "subagent.end",
  "prompt.submit",
  "compact",
  "gate.outcome",
  "cost.turn",
  "cost.session_alert",
  "ship.claim",
  "policy.deny",
  "policy.observe",
  "secret.masked",
  "pii.masked",
  "pii.written",
  "pii.disabled",
]);

export const LIVE_ALLOWLIST = new Set<ObsKind>([
  "session.start",
  "session.end",
  "generation.end",
  "tool.fail",
  "shell.end",
  "subagent.start",
  "subagent.end",
  "gate.outcome",
  "cost.turn",
  "cost.session_alert",
  "ship.claim",
  "policy.deny",
  "compact",
  "prompt.submit",
]);

export function resolveObsLevel(
  kind: ObsKind,
  attrs: Record<string, unknown> = {},
  forceDebug = false,
): ObsLevel {
  if (forceDebug) {
    return "debug";
  }
  // hazard: this branch used to key on `shell.end` alone, and a command that was denied or asked about never
  // reaches an "after" event — so the only permission it could ever grade was `allow`, and `rollup.shell.ask`
  // could not have moved even once the attribute was written. The decision is made at `shell.start`; that is the
  // only phase where a non-allow permission exists ([/decisions/ad-026.md](/decisions/ad-026.md)).
  if (kind === "shell.end" || kind === "shell.start") {
    const permission = String(attrs.permission ?? "allow");
    return permission === "allow" ? "debug" : "signal";
  }
  if (kind === "mcp.end") {
    const outcome = String(attrs.outcome ?? attrs.status ?? "success");
    return outcome === "error" || outcome === "fail" || outcome === "denied" ? "signal" : "debug";
  }
  return SIGNAL_KINDS.has(kind) ? "signal" : "debug";
}

export const EVENT_KIND_TO_OBS_KIND: Record<HarnessEventKind, ObsKind> = {
  "session.start": "session.start",
  "session.end": "session.end",
  "prompt.submit": "prompt.submit",
  "tool.before": "tool.start",
  "tool.after": "tool.end",
  "tool.failure": "tool.fail",
  "shell.before": "shell.start",
  "shell.after": "shell.end",
  "mcp.before": "mcp.start",
  "mcp.after": "mcp.end",
  "read.before": "file.read",
  "edit.after": "file.edit",
  "subagent.start": "subagent.start",
  "subagent.stop": "subagent.end",
  stop: "generation.end",
  "compact.before": "compact",
  "response.after": "agent.response",
  "thought.after": "agent.thought",
};

const SECRET_KEY = /(token|secret|password|api[_-]?key|authorization|credential|private[_-]?key)/i;
const SECRET_VALUE = /\b(ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g;

/**
 * hazard: this recognised three token shapes while the output rail recognised a dozen and every known value, so an
 * AWS key, a JWT or a `.env` password the model never saw was still written in clear to `audit.jsonl` and
 * `debug.jsonl` — the raw hook payload and the command line both reach disk through here
 * ([/decisions/ad-149.md](/decisions/ad-149.md)).
 *
 * invariant: what reaches disk is masked by the same known values and signatures that mask what reaches the model.
 *
 * hazard: not by the entropy pass. Its alphabet includes `/`, so a temp path like `/var/folders/3w/43yq…` scores
 * as a secret, and the records would lose the paths and diagnostics they exist to keep.
 */
function maskString(text: string, known: readonly KnownSecret[], pii: CompiledPiiTemplate | null): string {
  let masked = text;
  for (const match of [...scanForSecrets(text, known, { entropy: false })].reverse()) {
    masked = `${masked.slice(0, match.start)}[REDACTED:${match.kind}]${masked.slice(match.end)}`;
  }
  masked = masked.replace(SECRET_VALUE, "[REDACTED]");
  if (!pii) {
    return masked;
  }
  // why no hash on disk: a record is read by an operator, not joined by an agent, and leaving the hash out means the
  // writer never needs the salt.
  let out = masked;
  for (const match of [...scanForPii(masked, pii)].reverse()) {
    out = `${out.slice(0, match.start)}[PII:${match.kind}]${out.slice(match.end)}`;
  }
  return out;
}

export function redactDeep(
  value: unknown,
  known: readonly KnownSecret[] = [],
  pii: CompiledPiiTemplate | null = null,
): unknown {
  if (typeof value === "string") {
    return maskString(value, known, pii);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactDeep(item, known, pii));
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      out[key] = SECRET_KEY.test(key) ? "[REDACTED]" : redactDeep(nested, known, pii);
    }
    return out;
  }
  return value;
}
