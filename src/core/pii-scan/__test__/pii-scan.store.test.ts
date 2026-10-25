import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { withEnv } from "../../../../tools/test-env.scope.mjs";
import { pseudonymFor, sessionPseudonyms } from "../pii-scan.store.ts";
import type { KeepAttribute } from "../pii-scan.template.ts";
import { email, grouped, luhnComplete, phone } from "./pii-fixtures.ts";

const ALL: ReadonlySet<KeepAttribute> = new Set(["email-domain", "phone-country", "card-last4"]);

function inSandbox(run: (root: string) => void): void {
  const root = mkdtempSync(join(tmpdir(), "tlc-pii-store-"));
  const home = mkdtempSync(join(tmpdir(), "tlc-pii-home-"));
  try {
    withEnv({ TLC_HOME: home }, () => run(root));
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
}

test("the same value is the same token across sessions, and case or spacing does not split it", () => {
  inSandbox((root) => {
    const base = { root, kind: "email", mode: "pseudonym" as const, keep: ALL };
    const a = pseudonymFor({ ...base, sessionKey: "s1", value: email("Ana", "Corp-Fixture.io") });
    const b = pseudonymFor({ ...base, sessionKey: "s2", value: email("ana", "corp-fixture.io") });
    assert.equal(a, b);
    assert.match(a, /^\[PII:email:[0-9a-f]{8}@corp-fixture\.io\]$/);
    assert.deepEqual(sessionPseudonyms(root, "s1"), [a]);
  });
});

test("visible attributes keep a domain, a country and a card's brand and last four, and mask mode drops them", () => {
  inSandbox((root) => {
    const base = { root, sessionKey: "s", mode: "pseudonym" as const, keep: ALL };
    assert.match(pseudonymFor({ ...base, kind: "phone", value: phone("55 11 91234 5678") }), /:\+55\]$/);
    assert.match(pseudonymFor({ ...base, kind: "phone", value: phone("1 415 555 2671") }), /:\+1\]$/);
    const visa = grouped(luhnComplete("453914880343646"));
    assert.match(
      pseudonymFor({ ...base, kind: "card", value: visa }),
      new RegExp(`:visa…${visa.slice(-4)}\\]$`),
    );
    assert.match(
      pseudonymFor({ ...base, kind: "email", mode: "mask", value: email("ana", "corp-fixture.io") }),
      /^\[PII:email:[0-9a-f]{8}\]$/,
    );
  });
});

// hazard: an unsalted hash of a mailbox is a lookup key for anyone holding a list of mailboxes.
test("the token depends on the machine's salt, so it cannot be recomputed from the value alone", () => {
  const value = email("ana", "corp-fixture.io");
  const tokens: string[] = [];
  for (let run = 0; run < 2; run += 1) {
    inSandbox((root) => {
      tokens.push(pseudonymFor({ root, sessionKey: "s", kind: "email", mode: "mask", value, keep: ALL }));
    });
  }
  assert.notEqual(tokens[0], tokens[1]);
});
