import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { piiTemplatePath } from "../../../platform/paths.ts";
import { DEFAULT_PACKS } from "../pii-scan.packs.ts";
import { scanForPii } from "../pii-scan.service.ts";
import {
  compilePiiTemplate,
  loadPiiTemplate,
  loadPiiTemplateFor,
  normalizeLabel,
  otherTemplateRoots,
  stricterOf,
} from "../pii-scan.template.ts";
import { cpf, luhnComplete } from "./pii-fixtures.ts";

test("field names fold case, separators, camelCase and accents to one spelling", () => {
  for (const name of ["Customer-Email", "customer_email", "customerEmail", "CUSTOMER EMAIL"]) {
    assert.equal(normalizeLabel(name), "customer_email", name);
  }
  assert.equal(normalizeLabel("endereço"), "endereco");
});

test("with no template the default is international: checksummed id packs and every language pack", () => {
  const template = compilePiiTemplate(null);
  assert.equal(template.source, "default");
  assert.deepEqual(template.packs, [...DEFAULT_PACKS]);
  assert.equal(template.labels.get("nombre")?.kind, "name");
  assert.equal(
    template.labels.get("ssn"),
    undefined,
    "a label-only document waits for the project to declare it",
  );
});

test("extends composes jurisdictions without crossing them, and a project adds its own fields", () => {
  const template = compilePiiTemplate({
    extends: ["id:br", "id:us", "id:pt", "lang:pt"],
    fields: ["numero_conta", { name: "tenant", kind: "tenant", mode: "mask" }],
  });
  assert.deepEqual(template.packs, ["global", "id:br", "id:us", "id:pt", "lang:pt"]);
  assert.equal(template.labels.get("ssn")?.kind, "us-ssn");
  assert.equal(template.labels.get("nif")?.kind, "pt-nif");
  assert.equal(template.labels.get("numero_conta")?.kind, "custom");
  assert.deepEqual(template.labels.get("tenant"), { kind: "tenant", mode: "mask" });
  const doc = cpf("123456789");
  const kinds = scanForPii(`cpf ${doc}`, template).map((match) => match.kind);
  assert.deepEqual(kinds, ["br-cpf"]);
});

test("a custom pattern runs with the validator it names", () => {
  const template = compilePiiTemplate({
    patterns: [{ kind: "member", regex: "MBR-\\d{16}", validate: "luhn" }],
  });
  const valid = `MBR-${luhnComplete("453914880343646")}`;
  const invalid = `MBR-${luhnComplete("453914880343646").slice(0, -1)}0`;
  assert.deepEqual(
    scanForPii(`${valid} ${invalid}`, template).map((match) => match.kind),
    ["member"],
  );
});

test("a broken template reports what is wrong and still compiles the rest", () => {
  const template = compilePiiTemplate({
    extends: ["id:zz"],
    patterns: [
      { kind: "bad", regex: "(" },
      { kind: "unknown", regex: "x", validate: "rot13" },
    ],
    keep: ["email-domain", "shoe-size"],
  });
  assert.equal(template.errors.length, 4);
  assert.deepEqual(template.packs, ["global"]);
  assert.deepEqual([...template.keep], ["email-domain"]);
});

test("the template file is read from the project, and invalid JSON falls back to the defaults with an error", () => {
  const root = mkdtempSync(join(tmpdir(), "tlc-pii-template-"));
  try {
    mkdirSync(join(root, ".tlc", "harness"), { recursive: true });
    writeFileSync(piiTemplatePath(root), JSON.stringify({ extends: ["id:us"] }));
    assert.deepEqual(loadPiiTemplate(root).packs, ["global", "id:us"]);
    writeFileSync(piiTemplatePath(root), "{ not json");
    const broken = loadPiiTemplate(root);
    assert.equal(broken.source, "default");
    assert.match(broken.errors[0] ?? "", /not valid JSON/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function projectWith(template: object | null): string {
  const dir = mkdtempSync(join(tmpdir(), "pii-root-"));
  if (template !== null) {
    mkdirSync(join(dir, ".tlc", "harness"), { recursive: true });
    writeFileSync(join(dir, ".tlc", "harness", "pii.json"), JSON.stringify(template));
  }
  return dir;
}

// why: measured — a session in one repository ran `cd ../demo && curl …` and the demo's template was never read.
test("a command that moves into another project reads that project's template too", () => {
  const session = projectWith(null);
  const demo = projectWith({ fields: ["billing_zip_code_x"] });
  const command = `cd ${demo} && curl -s localhost:4317/v1/payments`;
  assert.deepEqual(otherTemplateRoots(session, { command }), [demo]);
  assert.ok(loadPiiTemplateFor(session, { command }).labels.has("billing_zip_code_x"));
  assert.ok(
    loadPiiTemplateFor(session, { filePath: join(demo, "src", "x.ts") }).labels.has("billing_zip_code_x"),
  );
  assert.deepEqual(otherTemplateRoots(session, { command: "curl -s localhost:4317" }), []);
});

// invariant: a template the session does not own can only add protection, whoever wrote it.
test("combining templates masks the union and exempts only what both exempt", () => {
  const mine = compilePiiTemplate({
    fields: [{ name: "notes", mode: "pseudonym" }],
    fixtures: { domains: ["qa.corp-fixture.io"], paths: ["seeds/**"] },
    ignore: ["company_name"],
  });
  const theirs = compilePiiTemplate({
    fields: [{ name: "notes", mode: "mask" }, "tenant"],
    fixtures: { domains: ["qa.corp-fixture.io", "everyone.io"], paths: ["**"] },
    keep: [],
    ignore: ["company_name", "customer_email"],
  });
  const merged = stricterOf(mine, theirs);
  assert.equal(merged.labels.get("notes")?.mode, "mask");
  assert.ok(merged.labels.has("tenant"));
  assert.deepEqual(merged.fixtureDomains, ["qa.corp-fixture.io"]);
  assert.deepEqual(merged.fixturePaths, []);
  assert.deepEqual([...merged.keep], []);
  assert.deepEqual([...merged.ignore], ["company_name"]);
  assert.equal(stricterOf(theirs, mine).labels.get("notes")?.mode, "mask");
});
