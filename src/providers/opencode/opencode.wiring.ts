import { join } from "node:path";
import type { ProviderWiring, RuntimePaths, WiringEntry } from "../../contracts/index.ts";
import { opencodeConfigDir } from "../../platform/paths.ts";
import { renderBridge } from "./opencode.bridge.ts";

type EntrySpec = {
  hookEvent: string;
  handler: string;
  timeoutSeconds: number;
  failClosed?: boolean;
};

// why: the hook names are the bridge's own (`opencode.inbound.ts` maps them), so they line up one to one with it.
const ENTRY_SPECS: readonly EntrySpec[] = [
  { hookEvent: "session.start", handler: "session-start", timeoutSeconds: 10 },
  { hookEvent: "session.prompt", handler: "prompt-submit", timeoutSeconds: 5 },
  { hookEvent: "tool.execute.before", handler: "tool-before", timeoutSeconds: 10, failClosed: true },
  { hookEvent: "tool.execute.after", handler: "tool-after", timeoutSeconds: 10 },
  { hookEvent: "tool.execute.failed", handler: "tool-failure", timeoutSeconds: 5 },
];

// why: `plugins/` is auto-discovered by OpenCode V2 in every config directory, so dropping the file there is the
// whole registration — no edit to the operator's `opencode.json` (`packages/core/src/plugin/source-directory.ts`).
export function opencodeBridgePath(): string {
  return join(opencodeConfigDir(), "plugins", "tlc-harness.js");
}

/**
 * why the config files too: `opencode.json`/`opencode.jsonc` decide which plugins load, so a write there can switch
 * the bridge off as surely as deleting it ([/decisions/ad-124.md](/decisions/ad-124.md)).
 */
export function opencodeWiringTargets(): string[] {
  const dir = opencodeConfigDir();
  return [opencodeBridgePath(), join(dir, "opencode.json"), join(dir, "opencode.jsonc")];
}

export function opencodeWiring(runtime: RuntimePaths): ProviderWiring {
  const entries: WiringEntry[] = ENTRY_SPECS.map((spec) => ({
    hookEvent: spec.hookEvent,
    handler: spec.handler,
    command: "node",
    args: [runtime.launcherPath, spec.handler],
    timeoutSeconds: spec.timeoutSeconds,
    ...(spec.failClosed !== undefined ? { failClosed: spec.failClosed } : {}),
  }));
  return {
    target: opencodeBridgePath(),
    strategy: "file",
    entries,
    content: renderBridge(entries),
    hostDir: opencodeConfigDir(),
  };
}
