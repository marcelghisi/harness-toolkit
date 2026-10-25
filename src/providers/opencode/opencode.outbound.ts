import type { Decision, HarnessEvent, Rendered } from "../../contracts/index.ts";

function render(body: Record<string, unknown>): Rendered {
  return { stdout: JSON.stringify(body), exitCode: 0 };
}

/**
 * why: the reply the bridge plugin reads back. It is this harness's own protocol, not a host schema: the bridge is the
 * only consumer, and `opencode.bridge.ts` applies each `action` to the live hook event.
 */
export function opencodeRender(decision: Decision, _event: HarnessEvent): Rendered {
  switch (decision.kind) {
    case "abstain":
      return { stdout: "{}", exitCode: 0 };
    case "allow":
      return render({ action: "allow" });
    case "deny":
      return render({ action: "deny", message: decision.reason });
    // hazard: unreachable after `degrade` (askSupportedOn is empty), but a direct render must still refuse — an
    // ask that rendered as anything softer would let the call through with nobody asked.
    case "ask":
      return render({ action: "deny", message: decision.reason });
    case "context":
      return render({ action: "context", text: decision.text });
    case "continue":
      return render({ action: "continue", text: decision.text });
    case "rewriteInput":
      return render({ action: "rewriteInput", input: decision.input });
    case "rewriteOutput":
      return render({ action: "rewriteOutput", content: decision.output });
    default: {
      const exhaustive: never = decision;
      throw new Error(`unreachable decision kind: ${JSON.stringify(exhaustive)}`);
    }
  }
}
