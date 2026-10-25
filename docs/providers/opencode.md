---
type: Provider
title: "OpenCode provider"
description: "The OpenCode V2 adapter — a generated plugin bridge, its capability descriptor, event mapping, and wiring target."
tags: [provider, opencode]
timestamp: "2026-10-24"
---

# OpenCode provider

Source: `src/providers/opencode/`. Targets OpenCode **V2** (`@opencode/plugin` 2.x), verified against the source at
tag `v2.1.4`. The V1 plugin API (`@opencode-ai/plugin` 1.x) is not supported — V2 never dispatches its hook names
([/decisions/ad-147.md](/decisions/ad-147.md)).

## How a hook reaches the harness

OpenCode runs plugins in-process and has no hook command. `tlc harness install` writes a generated plugin,
`tlc-harness.js`, into the config directory's `plugins/` folder, where V2 discovers it with no config edit. For each
hook it registers, the plugin spawns `node <runtime>/bin/tlc-exec.mjs <handler>` asynchronously, pipes a JSON
payload, and applies the reply to the live hook event:

| Reply | Applied as |
|---|---|
| `deny` | `throw` from `execute.before` — the host fails the tool call with the reason |
| `rewriteInput` | replaces `execute.before`'s `input` |
| `rewriteOutput` | replaces `execute.after`'s `result.content` — what the model reads |
| `context` (after a tool) | appended to `result.content` |
| `context` (session start) | appended to `system` on every request of that session |

`execute.before` fails closed: a spawn error, a timeout, an unparseable reply, or a reply with no `action` throws.
A handler that ran and had nothing to say answers `abstain`; a bare `{}` is what a runtime that did not recognise the
event writes, so it is treated as no answer. Every other hook fails open.
The code-mode wrapper `execute` is skipped, because V2 fires the hook again for each inner call, and a `patch` is
checked once per file its text names.

## Detection

`opencode.detect.ts` claims a payload carrying `provider: "opencode"` and a string `hook_event_name`. Only the
generated plugin builds these payloads, and its dotted hook names fail both Cursor's camelCase rule and Claude's
PascalCase one, so no payload matches two providers.

## Capability descriptor

`opencode.capabilities.ts`:

<!-- generated:capabilities -->

| Capability | Value |
|---|---|
| `enforcesHooks` | `true` |
| `askSupportedOn` | `[]` |
| `sessionEnv` | `false` |
| `nativeLoopCounter` | `false` |
| `dedicatedShellEvent` | `false` |
| `toolInputRewrite` | `true` |
| `toolOutputRewriteOn` | `["tool.after","shell.after","mcp.after","edit.after"]` |
| `contextAtToolBefore` | `false` |
| `contextAtToolAfter` | `true` |
| `contextAtStop` | `false` |
| `sessionStartContextReliable` | `true` |
| `toolOutputAtAfter` | `true` |
| `usageInPayload` | `false` |
| `effortSignal` | `false` |
| `thoughtEvent` | `false` |

<!-- /generated -->

## Policy defaults

No blocked model patterns and no minimum effort. `untrustedTools` is `WebFetch` and `WebSearch` — the names the
inbound normalizes `webfetch` and `websearch` to.

Tool names are normalized in `opencode.inbound.ts` so core keeps one spelling per tool: `shell`→`Bash`,
`read`→`Read`, `edit`/`patch`→`Edit`, `write`→`Write`, `subagent`→`Task`, `webfetch`→`WebFetch`,
`websearch`→`WebSearch`; the input field `path` (or `filePath`, or `file_path`) becomes `filePath`, and a `read` that names none of them is
refused, because the floor cannot judge a read it cannot name. `grep` with a `path` is a `read.before`,
because it returns the lines of the file it searches.

## Event mapping

`opencode.inbound.ts` maps the hook names the generated plugin stamps to `HarnessEventKind`:

<!-- generated:event-mapping -->

| Hook | Fan-out rule | HarnessEventKind |
|---|---|---|
| `session.start` | — | `session.start` |
| `session.prompt` | — | `prompt.submit` |
| `tool.execute.failed` | — | `tool.failure` |
| `tool.execute.before` | tool_name === "shell" | `shell.before` |
| `tool.execute.before` | tool_name matches `_` | `mcp.before` |
| `tool.execute.before` | tool_name === "read" | `read.before` |
| `tool.execute.before` | tool_name === "grep" | `read.before` |
| `tool.execute.after` | tool_name === "shell" | `shell.after` |
| `tool.execute.after` | tool_name matches `_` | `mcp.after` |
| `tool.execute.after` | tool_name === "edit" | `edit.after` |
| `tool.execute.after` | tool_name === "write" | `edit.after` |
| `tool.execute.after` | tool_name === "patch" | `edit.after` |

<!-- /generated -->

## Wiring target

Strategy `file`: `<config dir>/plugins/tlc-harness.js`, rendered whole by `opencode.bridge.ts`. The config dir is
`OPENCODE_CONFIG_DIR`, else `$XDG_CONFIG_HOME/opencode`, else `~/.config/opencode` — the order OpenCode itself uses.
`tlc harness doctor` reports it wired only while the file matches what install would write; `tlc harness uninstall`
removes it. `wiringTargets()` adds `opencode.json` and `opencode.jsonc`, which decide which plugins load, so the
`wiring-tamper` floor rule refuses an agent write to any of the three.

Not wired yet: the stop grind, subagent lifecycle and compaction — V2 has no hook that can keep a turn going.

## See also

- [/providers/index.md](/providers/index.md)
