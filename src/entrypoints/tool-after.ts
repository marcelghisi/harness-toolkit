import { relative } from "node:path";
import type { Decision, HarnessEvent, HarnessEventKind } from "../contracts/index.ts";
import { coreFacade, type ObsKind } from "../core/index.ts";
import { estimateCostUsd, mapPoolToNeutral } from "../platform/pricing.ts";
import { normalizeSeparators } from "../platform/sanitize.ts";
import { readClaudeUsage } from "../providers/index.ts";
import type { Handler, HandlerContext } from "./run.ts";
import { main } from "./run.ts";
import { OBS_CONFIG_AUDIT, obsConfigFor, observeForRules, resolveTurnBase } from "./support.ts";

const OBS_KIND_BY_EVENT: Partial<Record<HarnessEventKind, ObsKind>> = {
  "tool.after": "tool.end",
  "shell.after": "shell.end",
  "mcp.after": "mcp.end",
  "edit.after": "file.edit",
};

function rawString(raw: Record<string, unknown>, key: string): string | undefined {
  const value = raw[key];
  return typeof value === "string" ? value : undefined;
}

function rawBoolean(raw: Record<string, unknown>, key: string): boolean | undefined {
  const value = raw[key];
  return typeof value === "boolean" ? value : undefined;
}

function usageGenAi(event: HarnessEvent, ctx: HandlerContext): Record<string, unknown> | undefined {
  if (ctx.capabilities.usageInPayload || !event.transcriptPath) {
    return undefined;
  }
  const usage = readClaudeUsage(event.transcriptPath);
  if (!usage) {
    return undefined;
  }
  const cost = estimateCostUsd(event.provider, event.model, {
    inputTokens: usage.inputTokens,
    outputTokens: usage.outputTokens,
    cacheReadTokens: usage.cacheReadTokens,
    cacheWriteTokens: usage.cacheWriteTokens,
  });
  return {
    input_tokens: usage.inputTokens,
    output_tokens: usage.outputTokens,
    cache_read_tokens: usage.cacheReadTokens,
    cache_write_tokens: usage.cacheWriteTokens,
    cost_usd: cost.costUsd,
    cost_source: cost.source,
    cost_pool: mapPoolToNeutral(cost.pool),
  };
}

/**
 * why: this is cheaper than the stop-time scan and scoped to the file this edit touched, so it can afford
 * to run per edit — unlike duplication, which reads the whole tracked tree and stays stop-only
 * ([/decisions/ad-111.md](/decisions/ad-111.md)). It never blocks; a real violation still blocks at stop.
 */
async function commentEditAdvisory(event: HarnessEvent, ctx: HandlerContext): Promise<Decision | null> {
  const { policy } = ctx;
  if (!policy.comments.enabled || policy.comments.onViolation !== "followup" || !event.filePath) {
    return null;
  }
  const relativePath = normalizeSeparators(relative(event.projectDir, event.filePath));
  if (relativePath.startsWith("..") || !coreFacade.policy.isUnderCodePaths(relativePath, policy.codePaths)) {
    return null;
  }
  const targets = coreFacade.commentPolicy.filterCommentTargets([relativePath]);
  if (targets.length === 0) {
    return null;
  }
  const handoff = coreFacade.handoff.readHandoff(event.projectDir, event.provider, event.sessionKey);
  const hits = await coreFacade.commentPolicy.scanAddedComments(
    event.projectDir,
    targets,
    policy.comments.mode,
    await resolveTurnBase(handoff, event.projectDir),
  );
  if (hits.length === 0) {
    return null;
  }
  return { kind: "context", text: coreFacade.commentPolicy.commentEditAdvisory(hits, policy.comments.mode) };
}

function maskText(
  event: HarnessEvent,
  text: string,
  matches: readonly { start: number; end: number; kind: string }[],
): string {
  let masked = text;
  // why: reversed so each replacement's [start, end) offsets, computed against the original string, stay
  // valid as the string's length changes underneath earlier ones.
  for (const match of [...matches].reverse()) {
    const placeholder = coreFacade.secretScan.placeholderFor(
      event.projectDir,
      event.sessionKey,
      text.slice(match.start, match.end),
      match.kind,
    );
    masked = `${masked.slice(0, match.start)}${placeholder}${masked.slice(match.end)}`;
  }
  return masked;
}

// invariant: the subject is the command with its own secrets masked, or the path — never a raw value.
function leakSubject(
  event: HarnessEvent,
  commandMatches: readonly { start: number; end: number; kind: string }[],
): string {
  if (event.command) {
    return maskText(event, event.command, commandMatches).slice(0, 80);
  }
  if (event.filePath) {
    return normalizeSeparators(relative(event.projectDir, event.filePath));
  }
  return event.toolName ?? "tool";
}

/**
 * why the cause and not only the mask: a secret in an output is a defect in whatever printed it. The mask hides the
 * value; the classification names the defect, once per session and subject in the output itself, and counts it in
 * the session report for the operator ([/decisions/ad-149.md](/decisions/ad-149.md)).
 */
type Masked = { output: string; advice: string };

function redactSecrets(event: HarnessEvent, ctx: HandlerContext): Masked | null {
  if (!ctx.policy.secrets.redactOutput || !event.toolOutput) {
    return null;
  }
  const output = event.toolOutput;
  const known = ctx.policy.secrets.knownValues
    ? coreFacade.secretScan.loadKnownSecrets(event.projectDir)
    : [];
  const matches = coreFacade.secretScan.scanForSecrets(output, known);
  if (matches.length === 0) {
    return null;
  }
  const masked = maskText(event, output, matches);
  const commandMatches = event.command ? coreFacade.secretScan.scanForSecrets(event.command, known) : [];
  const cause = coreFacade.secretScan.classifyLeak({
    command: event.command,
    filePath: event.filePath,
    commandCarriesSecret: commandMatches.length > 0,
  });
  const subject = leakSubject(event, commandMatches);
  const kinds = [...new Set(matches.map((match) => match.kind))];
  coreFacade.observability.recordObs(event.projectDir, obsConfigFor(ctx.policy, OBS_CONFIG_AUDIT), {
    provider: event.provider,
    kind: "secret.masked",
    sessionKey: event.sessionKey,
    model: event.model,
    attrs: { cause, kinds, subject, event: event.event },
  });
  const fresh = coreFacade.secretScan.adviseOnce(event.projectDir, event.sessionKey, `${cause}:${subject}`);
  const advice = fresh ? `\n\n${coreFacade.secretScan.leakAdvice(cause, kinds, subject)}` : "";
  return { output: masked, advice };
}

function pseudonymise(event: HarnessEvent, text: string, matches: readonly PiiSpan[]): string {
  const template = coreFacade.piiScan.loadPiiTemplate(event.projectDir);
  let out = text;
  for (const match of [...matches].reverse()) {
    const token = coreFacade.piiScan.pseudonymFor({
      root: event.projectDir,
      sessionKey: event.sessionKey,
      value: text.slice(match.start, match.end),
      kind: match.kind,
      mode: match.mode,
      keep: template.keep,
    });
    out = `${out.slice(0, match.start)}${token}${out.slice(match.end)}`;
  }
  return out;
}

type PiiSpan = { start: number; end: number; kind: string; mode: "pseudonym" | "mask" };

// invariant: the subject is the command with its secrets and personal values already replaced, or the path.
function piiSubject(event: HarnessEvent, secretFree: string | undefined): string {
  if (secretFree) {
    const template = coreFacade.piiScan.loadPiiTemplate(event.projectDir);
    return pseudonymise(event, secretFree, coreFacade.piiScan.scanForPii(secretFree, template)).slice(0, 80);
  }
  if (event.filePath) {
    return normalizeSeparators(relative(event.projectDir, event.filePath));
  }
  return event.toolName ?? "tool";
}

/**
 * why after the secret mask: a credential is never personal data worth keeping correlatable, so it is masked first
 * and the personal-data pass runs on what is left. The same pass runs for a local container and a server, because
 * the rows are the same rows ([/decisions/ad-151.md](/decisions/ad-151.md)).
 */
function redactPii(
  event: HarnessEvent,
  ctx: HandlerContext,
  text: string,
  secretFreeCommand?: string,
): Masked | null {
  if (!ctx.policy.pii.redactOutput || text === "") {
    return null;
  }
  const template = coreFacade.piiScan.loadPiiTemplate(event.projectDir);
  const source = coreFacade.piiScan.classifyPiiSource({
    command: event.command,
    toolName: event.toolName,
    filePath: event.filePath,
  });
  const matches = coreFacade.piiScan.scanForPii(text, template, { fields: source !== "source-file" });
  if (matches.length === 0) {
    return null;
  }
  const subject = piiSubject(event, secretFreeCommand ?? event.command);
  const kinds = [...new Set(matches.map((match) => match.kind))];
  coreFacade.observability.recordObs(event.projectDir, obsConfigFor(ctx.policy, OBS_CONFIG_AUDIT), {
    provider: event.provider,
    kind: "pii.masked",
    sessionKey: event.sessionKey,
    model: event.model,
    attrs: { source, kinds, subject, count: matches.length, event: event.event },
  });
  const fresh = coreFacade.secretScan.adviseOnce(
    event.projectDir,
    event.sessionKey,
    `pii:${source}:${subject}`,
  );
  const advice = fresh ? `\n\n${coreFacade.piiScan.piiAdvice(source, kinds, subject)}` : "";
  return { output: pseudonymise(event, text, matches), advice };
}

function redactOutput(event: HarnessEvent, ctx: HandlerContext): Decision | null {
  if (!event.toolOutput) {
    return null;
  }
  const secrets = redactSecrets(event, ctx);
  const base = secrets?.output ?? event.toolOutput;
  const secretFreeCommand = event.command
    ? maskText(event, event.command, coreFacade.secretScan.scanForSecrets(event.command))
    : undefined;
  const pii = redactPii(event, ctx, base, secretFreeCommand);
  if (!secrets && !pii) {
    return null;
  }
  return {
    kind: "rewriteOutput",
    output: `${pii?.output ?? base}${secrets?.advice ?? ""}${pii?.advice ?? ""}`,
  };
}

export const toolAfterHandler: Handler = async (event: HarnessEvent, ctx: HandlerContext) => {
  // why here and not at `*.before`: arriving on an after-event is what says the tool ran and did not fail. A
  // failure comes as `tool.failure`, a different event this rail never sees, and the payload carries no exit code
  // in any of the three shapes the two hosts send ([/decisions/ad-100.md](/decisions/ad-100.md)).
  await observeForRules(event, ctx);

  coreFacade.observability.recordAudit(
    event.projectDir,
    event.event,
    event.raw,
    ctx.policy.obs.globalSpool,
    ctx.policy.secrets.knownValues,
    ctx.policy.pii.redactOutput,
  );

  const kind = OBS_KIND_BY_EVENT[event.event];
  if (kind) {
    const attrs: Record<string, unknown> = {
      tool_name: event.toolName,
      command: event.command,
      file_path: event.filePath,
    };
    if (event.event === "shell.after") {
      attrs.cwd = rawString(event.raw, "cwd");
      attrs.sandbox = rawBoolean(event.raw, "sandbox");
    }

    coreFacade.observability.recordObs(event.projectDir, obsConfigFor(ctx.policy, OBS_CONFIG_AUDIT), {
      provider: event.provider,
      kind,
      sessionKey: event.sessionKey,
      model: event.model,
      attrs,
      gen_ai: usageGenAi(event, ctx),
    });
  }

  // hazard: no degrade path consults contextAtToolAfter — the capability is declared but unread, so a
  // provider that cannot carry context on this event would swallow the framing and leave the rail reporting
  // a protection it never delivered. Abstaining keeps the marker unset, so a later event can still speak.
  if (!ctx.capabilities.contextAtToolAfter) {
    return { kind: "abstain" };
  }

  // why: recorded before the framing is decided, because the framing fires once per turn and the content of every
  // untrusted read still has to be remembered ([/decisions/ad-077.md](/decisions/ad-077.md)).
  if (ctx.provider.capabilities().toolOutputAtAfter) {
    coreFacade.untrusted.rememberUntrustedOutput({
      root: event.projectDir,
      sessionKey: event.sessionKey,
      event: event.event,
      toolName: event.toolName,
      command: event.command,
      toolOutput: event.toolOutput,
      config: ctx.policy.untrustedContent,
      providerTools: ctx.provider.policyDefaults().untrustedTools,
    });
  }

  const redacted = redactOutput(event, ctx);
  if (redacted) {
    return redacted;
  }

  const untrustedDecision = coreFacade.untrusted.evaluateUntrustedContent({
    root: event.projectDir,
    sessionKey: event.sessionKey,
    event: event.event,
    toolName: event.toolName,
    command: event.command,
    config: ctx.policy.untrustedContent,
    providerTools: ctx.provider.policyDefaults().untrustedTools,
  });
  if (untrustedDecision.kind !== "abstain") {
    return untrustedDecision;
  }

  if (event.event === "edit.after") {
    const advisory = await commentEditAdvisory(event, ctx);
    if (advisory) {
      return advisory;
    }
  }

  return { kind: "abstain" };
};

if (import.meta.main) {
  await main(toolAfterHandler);
}
