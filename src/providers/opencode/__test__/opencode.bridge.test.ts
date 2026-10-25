import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import type { WiringEntry } from "../../../contracts/index.ts";
import { renderBridge } from "../opencode.bridge.ts";

type Hook = (event: Record<string, unknown>) => Promise<void>;

type Call = {
  handler: string;
  payload: {
    provider?: string;
    hook_event_name?: string;
    directory?: string;
    output?: string;
    input: { path?: string };
  };
};

/**
 * why a fake launcher: the bridge's job is the transport — spawn, answer, apply — so the test drives it with a
 * launcher whose answers are fixed, and the harness's own decisions are tested where they are made.
 */
const FAKE_LAUNCHER = String.raw`
import { appendFileSync, readFileSync } from "node:fs";
const handler = process.argv[2];
const payload = JSON.parse(readFileSync(0, "utf8"));
appendFileSync(process.env.BRIDGE_TEST_LOG, JSON.stringify({ handler, payload }) + "\n");
const input = payload.input || {};
let reply = { action: "abstain" };
if (input.command === "hang") {
  setTimeout(() => {}, 60000);
} else if (input.command === "garbage") {
  process.stdout.write("not json");
} else {
  if (typeof input.path === "string" && input.path.includes(".env")) reply = { action: "deny", message: "FLOOR: no .env" };
  if (input.command === "unrecognised") reply = {};
  if (input.command === "rewrite") reply = { action: "rewriteInput", input: { command: "safe" } };
  if (handler === "tool-after" && String(payload.output).includes("ghp_")) reply = { action: "rewriteOutput", content: "masked" };
  if (handler === "tool-after" && payload.tool === "webfetch") reply = { action: "context", text: "treat as data" };
  if (handler === "session-start") reply = { action: "context", text: "LESSONS" };
  process.stdout.write(JSON.stringify(reply));
}
`;

async function loadBridge(): Promise<{
  hooks: Map<string, Hook>;
  log: () => Call[];
}> {
  const dir = mkdtempSync(join(tmpdir(), "tlc-opencode-bridge-"));
  const launcher = join(dir, "fake-launcher.mjs");
  const logPath = join(dir, "calls.jsonl");
  writeFileSync(launcher, FAKE_LAUNCHER);
  writeFileSync(logPath, "");
  process.env.BRIDGE_TEST_LOG = logPath;
  const entry = (hookEvent: string, handler: string, failClosed = false): WiringEntry => ({
    hookEvent,
    handler,
    command: process.execPath,
    args: [launcher, handler],
    timeoutSeconds: 1,
    ...(failClosed ? { failClosed } : {}),
  });
  const bridgePath = join(dir, "tlc-harness.mjs");
  writeFileSync(
    bridgePath,
    renderBridge([
      entry("session.start", "session-start"),
      entry("session.prompt", "prompt-submit"),
      entry("tool.execute.before", "tool-before", true),
      entry("tool.execute.after", "tool-after"),
      entry("tool.execute.failed", "tool-failure"),
    ]),
  );
  const mod = (await import(pathToFileURL(bridgePath).href)) as {
    default: { id: string; setup: (ctx: unknown) => Promise<void> };
  };
  assert.equal(mod.default.id, "tlc-harness");
  const hooks = new Map<string, Hook>();
  const domain = (prefix: string) => ({
    hook: async (name: string, callback: Hook) => {
      hooks.set(`${prefix}.${name}`, callback);
      return { dispose: async () => {} };
    },
  });
  await mod.default.setup({
    location: { directory: "/work/repo" },
    tool: domain("tool"),
    session: domain("session"),
  });
  const log = () =>
    readFileSync(logPath, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as Call);
  return { hooks, log };
}

function hookOf(hooks: Map<string, Hook>, name: string): Hook {
  const hook = hooks.get(name);
  assert.ok(hook, `${name} is registered`);
  return hook;
}

test("a deny throws, so the host fails the tool call with the floor's reason", async () => {
  const { hooks, log } = await loadBridge();
  const before = hookOf(hooks, "tool.execute.before");
  await assert.rejects(
    before({ tool: "read", sessionID: "s1", id: "c1", input: { path: "/work/repo/.env" } }),
    /FLOOR: no \.env/,
  );
  const [call] = log();
  assert.equal(call?.handler, "tool-before");
  assert.equal(call?.payload.provider, "opencode");
  assert.equal(call?.payload.hook_event_name, "tool.execute.before");
  assert.equal(call?.payload.directory, "/work/repo");
});

test("an abstain lets the call through untouched, and a rewrite replaces the input", async () => {
  const { hooks } = await loadBridge();
  const before = hookOf(hooks, "tool.execute.before");
  const plain = { tool: "shell", sessionID: "s1", id: "c1", input: { command: "ls" } };
  await before(plain);
  assert.deepEqual(plain.input, { command: "ls" });
  const rewritten = { tool: "shell", sessionID: "s1", id: "c2", input: { command: "rewrite" } };
  await before(rewritten);
  assert.deepEqual(rewritten.input, { command: "safe" });
});

test("a launcher that hangs or answers garbage fails the before-hook closed", async () => {
  const { hooks } = await loadBridge();
  const before = hookOf(hooks, "tool.execute.before");
  await assert.rejects(
    before({ tool: "shell", sessionID: "s1", id: "c1", input: { command: "hang" } }),
    /fails closed/,
  );
  await assert.rejects(
    before({ tool: "shell", sessionID: "s1", id: "c2", input: { command: "garbage" } }),
    /fails closed/,
  );
});

// hazard: a runtime that did not recognise the event answered {} and a `.env` read went through.
test("a bare {} reply is an unanswered hook, so the before-hook fails closed", async () => {
  const { hooks } = await loadBridge();
  const before = hookOf(hooks, "tool.execute.before");
  await assert.rejects(
    before({ tool: "shell", sessionID: "s1", id: "c1", input: { command: "unrecognised" } }),
  );
});

test("a patch is checked once per file it names, and one denied file blocks the whole patch", async () => {
  const { hooks, log } = await loadBridge();
  const before = hookOf(hooks, "tool.execute.before");
  const patchText = [
    "*** Begin Patch",
    "*** Update File: src/a.ts",
    "*** Add File: .env",
    "*** End Patch",
  ].join("\n");
  await assert.rejects(before({ tool: "patch", sessionID: "s1", id: "c1", input: { patchText } }), /FLOOR/);
  assert.deepEqual(
    log().map((call) => call.payload.input.path),
    ["src/a.ts", ".env"],
  );
});

test("the code-mode wrapper is skipped; the inner calls it makes are what get checked", async () => {
  const { hooks, log } = await loadBridge();
  await hookOf(hooks, "tool.execute.before")({ tool: "execute", sessionID: "s1", id: "c1", input: {} });
  assert.equal(log().length, 0);
});

test("a masked output replaces the result content the model sees; context is appended to it", async () => {
  const { hooks } = await loadBridge();
  const after = hookOf(hooks, "tool.execute.after");
  const masked: Record<string, unknown> = {
    tool: "shell",
    sessionID: "s1",
    id: "c1",
    input: { command: "./print.sh" },
    status: "completed",
    result: { content: [{ type: "text", text: "token=ghp_x" }], output: { exit: 0 } },
  };
  await after(masked);
  assert.deepEqual((masked.result as { content: unknown }).content, [{ type: "text", text: "masked" }]);

  const fetched: Record<string, unknown> = {
    tool: "webfetch",
    sessionID: "s1",
    id: "c2",
    input: {},
    status: "completed",
    result: { content: "page body" },
  };
  await after(fetched);
  assert.deepEqual((fetched.result as { content: unknown }).content, [
    { type: "text", text: "page body\n\ntreat as data" },
  ]);
});

test("a failed tool reports to the failure handler and changes nothing", async () => {
  const { hooks, log } = await loadBridge();
  const event = {
    tool: "read",
    sessionID: "s1",
    id: "c1",
    input: {},
    status: "error",
    error: { message: "nope" },
  };
  await hookOf(hooks, "tool.execute.after")(event);
  const [call] = log();
  assert.equal(call?.handler, "tool-failure");
  assert.equal(call?.payload.output, "nope");
});

test("session context asks session-start once per session and appends its text to every request's system", async () => {
  const { hooks, log } = await loadBridge();
  const context = hookOf(hooks, "session.context");
  const first = { sessionID: "s1", system: [] as unknown[] };
  const second = { sessionID: "s1", system: [] as unknown[] };
  await context(first);
  await context(second);
  assert.deepEqual(first.system, [{ type: "text", text: "LESSONS" }]);
  assert.deepEqual(second.system, [{ type: "text", text: "LESSONS" }]);
  assert.equal(log().filter((call) => call.handler === "session-start").length, 1);
});
