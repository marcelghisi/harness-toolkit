import type { ProviderCapabilities } from "../../contracts/index.ts";

export function claudeCapabilities(): ProviderCapabilities {
  return {
    enforcesHooks: true,
    askSupportedOn: ["tool.before", "shell.before", "mcp.before", "read.before"],
    sessionEnv: false,
    nativeLoopCounter: false,
    dedicatedShellEvent: false,
    toolInputRewrite: true,
    // why: `updatedToolOutput` is documented on PostToolUse only, and PostToolUse fans out by tool name, so its Bash,
    // MCP and edit kinds are listed beside `tool.after`. PostToolUseFailure documents `additionalContext` alone, so a
    // failure's output is never claimed rewritable ([/decisions/ad-148.md](/decisions/ad-148.md)).
    toolOutputRewriteOn: ["tool.after", "shell.after", "mcp.after", "edit.after"],
    contextAtToolBefore: true,
    contextAtToolAfter: true,
    // why: `Stop` accepts `hookSpecificOutput.additionalContext` for feedback that continues the turn, which is
    // exactly what a non-blocking gate advisory is.
    contextAtStop: true,
    // why: `SessionStart` delivers `hookSpecificOutput.additionalContext`, capped at 10,000 characters. Only that
    // field — a top-level `additional_context` is read as well and not deduplicated, so emitting both injects twice.
    sessionStartContextReliable: true,
    toolOutputAtAfter: true,
    usageInPayload: false,
    effortSignal: true,
    thoughtEvent: false,
  };
}
