import assert from "node:assert/strict";
import { test } from "node:test";
import { scanForPii } from "../pii-scan.service.ts";
import { compilePiiTemplate } from "../pii-scan.template.ts";
import { cpf, dni, email, grouped, iban, luhnComplete, phone } from "./pii-fixtures.ts";

const DEFAULT = compilePiiTemplate(null);

function found(text: string, template = DEFAULT, fields = true): [string, string][] {
  return scanForPii(text, template, { fields }).map((match) => [
    match.kind,
    text.slice(match.start, match.end),
  ]);
}

test("psql, mysql, CSV and sqlite -header output mask the cells under a personal column", () => {
  const mail = email("ana.souza", "gmail.com");
  const psql = ` id | name      | email\n----+-----------+------\n  1 | Ana Souza | ${mail}\n(1 row)`;
  assert.deepEqual(found(psql), [
    ["name", "Ana Souza"],
    ["email", mail],
  ]);
  const mysql = "+----+-------+\n| id | nome  |\n+----+-------+\n|  1 | Ana   |\n+----+-------+";
  assert.deepEqual(found(mysql), [["name", "Ana"]]);
  assert.deepEqual(found("id,first_name,city\n1,Ana,Lisboa"), [["name", "Ana"]]);
  assert.deepEqual(found("id|last_name\n1|Souza"), [["name", "Souza"]]);
});

test("a JSON field, a key=value and a key: value are masked by their label, value only", () => {
  const doc = cpf("123456789");
  assert.deepEqual(found(`{"user":{"full_name":"Ana Souza","age":31,"cpf":"${doc}"}}`), [
    ["name", "Ana Souza"],
    ["br-cpf", doc],
  ]);
  assert.deepEqual(found("login ip_address=10.1.2.3 name: Ana Souza, ok"), [
    ["ip", "10.1.2.3"],
    ["name", "Ana Souza"],
  ]);
  assert.deepEqual(found(`customer_phone=${phone("351912345678")}`), [["phone", phone("351912345678")]]);
});

test("a value shaped like a document, a card, an IBAN or an E.164 phone is found without a label", () => {
  const visa = grouped(luhnComplete("453914880343646"));
  const account = iban("DE", "370400440532013000");
  const id = dni("12345678");
  const mobile = phone("44 7911 123456");
  assert.deepEqual(found(`paid with ${visa} from ${account}; dni ${id}; call ${mobile}`), [
    ["card", visa],
    ["iban", account],
    ["es-dni", id],
    ["phone", mobile],
  ]);
});

// invariant: these are the shapes a careful system and a test suite already use in place of a person.
test("reserved domains, role mailboxes, issuer test cards, invalid checksums and placeholders are left alone", () => {
  const text = [
    email("fixture.user", "example.invalid"),
    email("support", "corp-fixture.io"),
    email("someone", "users.noreply.github.com"),
    "4242 4242 4242 4242",
    "123.456.789-00",
    'name="[REDACTED]"',
    `email=${"$"}{USER_EMAIL}`,
  ].join(" ");
  assert.deepEqual(found(text), []);
});

test("code that names a field is not personal data: an expression or a type stays readable", () => {
  assert.deepEqual(found("const user = { name: string; email: user.email }"), []);
  assert.deepEqual(found("name: getName(user)"), []);
});

test("with fields off, as for a source file, only self-proving shapes are found", () => {
  const mail = email("ana", "corp-fixture.io");
  assert.deepEqual(found(`const seed = { name: "Ana Souza", email: "${mail}" }`, DEFAULT, false), [
    ["email", mail],
  ]);
});

test("a project's fixture domain is a fixture", () => {
  const template = compilePiiTemplate({ fixtures: { domains: ["e2e.test", "qa.corp-fixture.io"] } });
  assert.deepEqual(found(email("user", "qa.corp-fixture.io"), template), []);
  assert.deepEqual(found(email("user", "a.qa.corp-fixture.io"), template), []);
});

test("spans a secret mask already took are not claimed again", () => {
  const mail = email("ana", "corp-fixture.io");
  const text = `token=abc ${mail}`;
  const start = text.indexOf(mail);
  assert.deepEqual(scanForPii(text, DEFAULT, { taken: [{ start, end: start + mail.length }] }), []);
});

test("a special-category label is masked in mask mode", () => {
  const template = compilePiiTemplate({ extends: ["domain:health"] });
  const matches = scanForPii('{"patient_id":"P-1","diagnosis":"J45"}', template);
  assert.deepEqual(
    matches.map((match) => [match.kind, match.mode]),
    [
      ["health", "mask"],
      ["health", "mask"],
    ],
  );
});

test("noise that resembles personal data is not personal data", () => {
  const text =
    "commit by x@host version +1.2.3 order 12345678901 uuid 550e8400-e29b-41d4-a716-446655440000 port +12 sha 3f786850e387550fdab836ed7e6dc881de23001b";
  assert.deepEqual(found(text), []);
});
