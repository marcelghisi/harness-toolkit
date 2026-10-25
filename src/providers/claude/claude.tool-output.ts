import type { HarnessEvent } from "../../contracts/index.ts";

/**
 * invariant: a separator no detector can match and no shell prints — a NUL-framed word — so the scanned text splits
 * back into the two streams exactly where it was joined.
 */
const STREAM_SEPARATOR = "\n\u0000stderr\u0000\n";

type ShellStreams = { stdout: string; stderr: string; rest: Record<string, unknown> };

// why: Bash answers `{stdout, stderr, interrupted, isImage}`. Scanning the serialised object escaped every newline,
// so a psql table reached the scanner as one line and no column could be read.
export function shellStreams(value: unknown): ShellStreams | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  if (typeof record.stdout !== "string") {
    return null;
  }
  return {
    stdout: record.stdout,
    stderr: typeof record.stderr === "string" ? record.stderr : "",
    rest: record,
  };
}

export function joinStreams(stdout: string, stderr: string): string {
  return stderr === "" ? stdout : `${stdout}${STREAM_SEPARATOR}${stderr}`;
}

/**
 * The replacement output in the shape the tool itself returned.
 *
 * hazard: Claude Code ignores an `updatedToolOutput` that does not match the tool's output schema and keeps the
 * original, silently. A masked string sent for Bash, whose output is an object, was dropped and the model read every
 * value the mask had hidden — measured live on a users query.
 *
 * invariant: null when the shape cannot be rebuilt, so the caller says so instead of sending something ignored.
 */
export function shapedToolOutput(event: HarnessEvent, output: string): unknown {
  const original = event.raw.tool_response;
  if (typeof original === "string") {
    return output;
  }
  const shell = shellStreams(original);
  if (shell) {
    const at = output.indexOf(STREAM_SEPARATOR);
    const stdout = at === -1 ? output : output.slice(0, at);
    const stderr = at === -1 ? "" : output.slice(at + STREAM_SEPARATOR.length);
    return { ...shell.rest, stdout, stderr };
  }
  try {
    return JSON.parse(output) as unknown;
  } catch {
    return null;
  }
}
