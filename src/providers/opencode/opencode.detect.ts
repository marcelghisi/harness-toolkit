/**
 * why: OpenCode runs plugins in-process and has no command hooks of its own, so every payload this adapter sees
 * was built by the bridge plugin `opencode.bridge.ts` renders. The bridge stamps `provider: "opencode"` and a
 * dotted `hook_event_name` — a dotted name fails both Cursor's camelCase rule and Claude's PascalCase one, so
 * the three detectors cannot claim the same payload.
 */
export function detectOpencode(raw: unknown): boolean {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    return false;
  }
  const value = raw as Record<string, unknown>;
  return value.provider === "opencode" && typeof value.hook_event_name === "string";
}
