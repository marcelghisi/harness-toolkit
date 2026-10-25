import type { ProviderPort } from "../provider.port.ts";
import { opencodeCapabilities } from "./opencode.capabilities.ts";
import { detectOpencode } from "./opencode.detect.ts";
import { opencodeToEvent } from "./opencode.inbound.ts";
import { opencodeRender } from "./opencode.outbound.ts";
import { opencodePolicyDefaults } from "./opencode.policy-defaults.ts";
import { opencodeWiring, opencodeWiringTargets } from "./opencode.wiring.ts";

// why: assembled here so the scaffold has one ProviderPort to append into provider.registry.ts.
export const opencodeProvider: ProviderPort = {
  name: "opencode",
  detect: detectOpencode,
  capabilities: opencodeCapabilities,
  policyDefaults: opencodePolicyDefaults,
  toEvent: opencodeToEvent,
  render: opencodeRender,
  wiring: opencodeWiring,
  wiringTargets: opencodeWiringTargets,
  // why: null until this host has its own durable lessons view (see cursor.lessons-view.ts / claude.lessons-view.ts for the shape a real one takes).
  lessonsView: (_root: string): string | null => null,
};
