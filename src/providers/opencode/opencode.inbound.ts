import type { HarnessEvent, HarnessEventKind } from "../../contracts/index.ts";
import { sanitizeSegment } from "../../platform/sanitize.ts";

/**
 * why: these are the names the bridge plugin stamps, not OpenCode's own registrations. `session.start` has no V2
 * hook of its own — the bridge raises it on the first `session` `context` hook of a session.
 */
export const EVENT_KIND_BY_HOOK: Record<string, HarnessEventKind> = {
  "session.start": "session.start",
  "session.prompt": "prompt.submit",
  "tool.execute.failed": "tool.failure",
};

// why: V2 registers an MCP tool as `<server>_<tool>`, and no built-in tool name carries an underscore
// (`packages/core/src/tool/mcp.ts` at v2.1.4).
const MCP_TOOL_NAME = /_/;

type ToolNameFanOutRule = { match: RegExp | string; kind: HarnessEventKind };

export const FAN_OUT_HOOK_NAMES = { pre: "tool.execute.before", post: "tool.execute.after" } as const;

// why: `execute.before` fires for every tool — V2 has no dedicated shell, MCP or read event, so the kind comes
// from the tool name, matched against the host's own lowercase name.
export const PRE_TOOL_USE_FAN_OUT: readonly ToolNameFanOutRule[] = [
  { match: "shell", kind: "shell.before" },
  { match: MCP_TOOL_NAME, kind: "mcp.before" },
  { match: "read", kind: "read.before" },
  // why: `grep` returns the matching lines of the file it searches, so a `grep` over `.env` is a read of `.env`.
  { match: "grep", kind: "read.before" },
];

export const POST_TOOL_USE_FAN_OUT: readonly ToolNameFanOutRule[] = [
  { match: "shell", kind: "shell.after" },
  { match: MCP_TOOL_NAME, kind: "mcp.after" },
  { match: "edit", kind: "edit.after" },
  { match: "write", kind: "edit.after" },
  { match: "patch", kind: "edit.after" },
];

/**
 * invariant: every rail in core names tools the way the first two hosts do (`Bash`, `Read`, `Write`, `Task`), so
 * the translation happens here and core never learns a third spelling. `raw.tool` keeps the host's own name.
 */
const TOOL_NAME_BY_HOST: Record<string, string> = {
  shell: "Bash",
  read: "Read",
  grep: "Grep",
  glob: "Glob",
  edit: "Edit",
  write: "Write",
  // why: a patch edits files in place; `Edit` is the name the write and policy-surface rails already guard.
  patch: "Edit",
  subagent: "Task",
  webfetch: "WebFetch",
  websearch: "WebSearch",
};

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function matchFanOut(
  table: readonly ToolNameFanOutRule[],
  toolName: string | undefined,
  fallback: HarnessEventKind,
): HarnessEventKind {
  if (toolName === undefined) {
    return fallback;
  }
  for (const rule of table) {
    const matched = typeof rule.match === "string" ? rule.match === toolName : rule.match.test(toolName);
    if (matched) {
      return rule.kind;
    }
  }
  return fallback;
}

function eventKindFor(hookEventName: string, hostTool: string | undefined): HarnessEventKind | undefined {
  if (hookEventName === FAN_OUT_HOOK_NAMES.pre) {
    return matchFanOut(PRE_TOOL_USE_FAN_OUT, hostTool, "tool.before");
  }
  if (hookEventName === FAN_OUT_HOOK_NAMES.post) {
    return matchFanOut(POST_TOOL_USE_FAN_OUT, hostTool, "tool.after");
  }
  return EVENT_KIND_BY_HOOK[hookEventName];
}

function copyText(event: HarnessEvent, field: "text" | "toolOutput" | "model", value: unknown): void {
  const text = asString(value);
  if (text !== undefined && (text !== "" || field !== "model")) {
    event[field] = text;
  }
}

function sessionKeyFor(raw: Record<string, unknown>): string {
  const seed = asString(raw.session_id) || "default";
  return `opencode-${sanitizeSegment(seed)}`;
}

function projectDirFor(raw: Record<string, unknown>): string {
  return asString(raw.directory) || process.cwd();
}

type EventField =
  | "command"
  | "cwd"
  | "filePath"
  | "proposedContent"
  | "proposedOldContent"
  | "spawnSubagentType"
  | "spawnModel";

const COMMON_FIELDS: readonly [string, EventField][] = [
  ["command", "command"],
  ["workdir", "cwd"],
  ["path", "filePath"],
];

const FIELDS_BY_TOOL: Record<string, readonly [string, EventField][]> = {
  write: [["content", "proposedContent"]],
  edit: [
    ["newString", "proposedContent"],
    ["oldString", "proposedOldContent"],
  ],
  subagent: [
    ["agent", "spawnSubagentType"],
    ["model", "spawnModel"],
  ],
};

// hazard: an empty string is a value for file content and nothing for a path or a cwd — an empty cwd outranked the
// real project root on another host ([/decisions/ad-141.md](/decisions/ad-141.md)).
const EMPTY_IS_A_VALUE = new Set<EventField>(["proposedContent", "proposedOldContent"]);

function copyFields(
  event: HarnessEvent,
  input: Record<string, unknown>,
  fields: readonly [string, EventField][],
): void {
  for (const [from, to] of fields) {
    const value = asString(input[from]);
    if (value !== undefined && (value !== "" || EMPTY_IS_A_VALUE.has(to))) {
      event[to] = value;
    }
  }
}

function applyToolFields(
  event: HarnessEvent,
  hostTool: string,
  input: Record<string, unknown> | undefined,
): void {
  event.toolName = TOOL_NAME_BY_HOST[hostTool] ?? hostTool;
  if (!input) {
    return;
  }
  event.toolInput = input;
  copyFields(event, input, COMMON_FIELDS);
  copyFields(event, input, FIELDS_BY_TOOL[hostTool] ?? []);
}

/** Never throws on a malformed payload — returns null instead. */
export function opencodeToEvent(raw: Record<string, unknown>): HarnessEvent | null {
  const hookEventName = asString(raw.hook_event_name);
  if (!hookEventName) {
    return null;
  }
  const hostTool = asString(raw.tool);
  const eventKind = eventKindFor(hookEventName, hostTool);
  if (!eventKind) {
    return null;
  }

  const event: HarnessEvent = {
    provider: "opencode",
    event: eventKind,
    sessionKey: sessionKeyFor(raw),
    projectDir: projectDirFor(raw),
    raw,
  };

  copyText(event, "model", raw.model);

  if (eventKind === "prompt.submit") {
    copyText(event, "text", raw.prompt);
    return event;
  }
  if (hostTool !== undefined) {
    applyToolFields(event, hostTool, asRecord(raw.input));
  }
  copyText(event, "toolOutput", raw.output);
  return event;
}
