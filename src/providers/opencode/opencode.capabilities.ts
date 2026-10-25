import type { ProviderCapabilities } from "../../contracts/index.ts";

/**
 * why each value: read from the OpenCode V2 source at tag `v2.1.4` (`anomalyco/opencode`), not from the V1 docs
 * site, whose hook names V2 never dispatches ([/decisions/ad-147.md](/decisions/ad-147.md)).
 */
export function opencodeCapabilities(): ProviderCapabilities {
  return {
    enforcesHooks: true,
    // why: empty, because a plugin blocks a tool by throwing from `execute.before`, and a throw has no "ask the operator"
    // form. `degrade` turns every ask into a deny that says so, which is the honest ceiling.
    askSupportedOn: [],
    sessionEnv: false,
    nativeLoopCounter: false,
    dedicatedShellEvent: false,
    // why: `execute.before`'s `input` is mutable and core passes the mutated value to the tool
    // (`packages/core/src/tool.ts`).
    toolInputRewrite: true,
    // why: `execute.after`'s `result` is re-read by core after the hook chain, so replacing its `content` is what
    // the model sees — for every tool class, MCP included (`packages/plugin/src/promise/tool.ts`).
    toolOutputRewriteOn: ["tool.after", "shell.after", "mcp.after", "edit.after"],
    contextAtToolBefore: false,
    // why: carried by appending to the completed result's content — the only model-visible channel on this event.
    contextAtToolAfter: true,
    contextAtStop: false,
    // why: the bridge answers the first `session` `context` hook of each session by appending to `system`, which
    // every model request of that session carries.
    sessionStartContextReliable: true,
    toolOutputAtAfter: true,
    usageInPayload: false,
    effortSignal: false,
    thoughtEvent: false,
  };
}
