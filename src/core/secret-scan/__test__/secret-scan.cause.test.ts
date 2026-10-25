import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyLeak, leakAdvice } from "../secret-scan.cause.ts";

function cause(command?: string, filePath?: string, commandCarriesSecret = false): string {
  return classifyLeak({ command, filePath, commandCarriesSecret });
}

test("reading a log, from a file or a platform's logs command, is a logged credential", () => {
  for (const command of [
    "cat app.log",
    "tail -n 200 /var/log/api/error.log",
    "grep -i password logs/app.txt",
    "docker compose logs api",
    "kubectl logs deploy/api",
    "journalctl -u api",
  ]) {
    assert.equal(cause(command), "logged-credential", command);
  }
  assert.equal(cause(undefined, "logs/app.log"), "logged-credential");
});

test("a credential on the command line wins over what the command reads", () => {
  assert.equal(cause("mysql -uroot -phunter2 -e 'select 1'"), "argv-credential");
  assert.equal(cause('curl -H "Authorization: Bearer x" https://api'), "argv-credential");
  assert.equal(cause("psql postgres://app@db", undefined, true), "argv-credential");
  assert.equal(cause("cat app.log", undefined, true), "argv-credential");
});

test("dumping the environment is its own cause; an ordinary command is other", () => {
  assert.equal(cause("env"), "env-dump");
  assert.equal(cause("printenv | sort"), "env-dump");
  assert.equal(cause("npm test"), "other");
  assert.equal(cause("environment-check"), "other");
});

test("a source or config file read is a hardcoded credential; anything else is other", () => {
  assert.equal(cause(undefined, "src/db/config.ts"), "hardcoded");
  assert.equal(cause(undefined, "deploy/values.yaml"), "hardcoded");
  assert.equal(cause(undefined, "notes/readme.md"), "other");
  assert.equal(cause(), "other");
});

test("the advice names the cause, the subject and the variables, and points at metadata rather than the value", () => {
  const advice = leakAdvice("logged-credential", ["env:DB_PASSWORD", "env:DB_PASSWORD"], "cat app.log");
  assert.match(advice, /^\[SECRET-HYGIENE logged-credential\] cat app\.log exposed env:DB_PASSWORD; /);
  assert.match(advice, /debug included/);
  assert.match(advice, /metadata instead of the value/);
  assert.match(advice, /tell the operator instead/);
});
