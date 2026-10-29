import assert from "node:assert/strict";
import { test } from "node:test";
import { brCnpj, brCpf, card, e164, esDni, frNir, luhn, mod97 } from "../pii-scan.validators.ts";
import { cnpj, cpf, dni, iban, luhnComplete, nir } from "./pii-fixtures.ts";

test("each checksum accepts the value built to satisfy it and refuses one digit off", () => {
  const cases: [(text: string) => boolean, string][] = [
    [brCpf, cpf("123456789")],
    [brCnpj, cnpj("112223330001")],
    [mod97, iban("DE", "370400440532013000")],
    [esDni, dni("12345678")],
    [frNir, nir("1840775123456")],
    [luhn, luhnComplete("453914880343646")],
  ];
  for (const [validate, value] of cases) {
    assert.equal(validate(value), true, value);
    const last = value.at(-1) ?? "0";
    const off = /\d/.test(last)
      ? `${value.slice(0, -1)}${(Number(last) + 1) % 10}`
      : `${value.slice(0, -1)}A`;
    assert.equal(validate(off), false, off);
  }
});

test("a repeated-digit document and an all-zero card are not documents", () => {
  assert.equal(brCpf("111.111.111-11"), false);
  assert.equal(brCnpj("00.000.000/0000-00"), false);
  assert.equal(card("0000000000000000"), false);
});

test("a card needs an issuer prefix and a card length besides Luhn", () => {
  assert.equal(card(luhnComplete("453914880343646")), true);
  assert.equal(card(luhnComplete("123456789012345")), false);
  assert.equal(card(luhnComplete("45391488")), false);
});

test("an E.164 phone has eight to fifteen digits", () => {
  assert.equal(e164("+1 234"), false);
  assert.equal(e164(["+", "55 11 9123 4567"].join("")), true);
  assert.equal(e164(["+", "1234567890123456"].join("")), false);
});
