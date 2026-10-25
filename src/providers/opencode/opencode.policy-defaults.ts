import type { ProviderPolicyDefaults } from "../../contracts/index.ts";

export function opencodePolicyDefaults(): ProviderPolicyDefaults {
  return {
    blockedPatterns: [],
    minEffort: null,
    // invariant: the normalized names `opencode.inbound.ts` produces, not the host's lowercase `webfetch`.
    untrustedTools: ["WebFetch", "WebSearch"],
  };
}
