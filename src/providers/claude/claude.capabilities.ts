import type { ProviderCapabilities } from "../../contracts/index.ts";

export function claudeCapabilities(): ProviderCapabilities {
  return {
    enforcesHooks: true,
    askSupportedOn: ["tool.before", "shell.before", "mcp.before", "read.before"],
    sessionEnv: false,
    nativeLoopCounter: false,
    dedicatedShellEvent: false,
    toolInputRewrite: true,
    // why: `updatedToolOutput` is valid on PostToolUse and PostToolUseFailure, and PostToolUse fans out by tool
    // name, so its Bash, MCP and edit kinds are listed beside `tool.after` — leaving them out turned every masked
    // shell output into a notice the model read beside the raw value ([/decisions/ad-148.md](/decisions/ad-148.md)).
    toolOutputRewriteOn: ["tool.after", "tool.failure", "shell.after", "mcp.after", "edit.after"],
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
