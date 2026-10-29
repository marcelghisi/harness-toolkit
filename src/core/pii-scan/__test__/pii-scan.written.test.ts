import assert from "node:assert/strict";
import { test } from "node:test";
import { compilePiiTemplate } from "../pii-scan.template.ts";
import { findAddedPii, writtenPiiFollowup } from "../pii-scan.written.ts";
import { cpf, email } from "./pii-fixtures.ts";

const DEFAULT = compilePiiTemplate(null);

test("a mailbox or a valid document added to source is found; a field name beside a string is not", () => {
  const findings = findAddedPii(
    [
      { file: "src/seed.ts", line: 3, text: `const admin = "${email("ana", "corp-fixture.io")}";` },
      { file: "src/seed.ts", line: 4, text: `const doc = "${cpf("123456789")}";` },
      { file: "src/seed.ts", line: 5, text: 'const user = { name: "Ana Souza" };' },
      { file: "src/seed.ts", line: 6, text: `// contact ${email("dev", "example.com")}` },
    ],
    DEFAULT,
  );
  assert.deepEqual(findings, [
    { file: "src/seed.ts", line: 3, kind: "email" },
    { file: "src/seed.ts", line: 4, kind: "br-cpf" },
  ]);
});

test("in a config or log file a labelled value counts too", () => {
  const findings = findAddedPii(
    [{ file: "config/users.yaml", line: 2, text: "full_name: Ana Souza" }],
    DEFAULT,
  );
  assert.deepEqual(findings, [{ file: "config/users.yaml", line: 2, kind: "name" }]);
});

test("a path the project lists as fixtures is skipped", () => {
  const template = compilePiiTemplate({ fixtures: { paths: ["backups/e2e/**", "test/*.json"] } });
  const line = `"${email("ana", "corp-fixture.io")}"`;
  assert.deepEqual(
    findAddedPii(
      [
        { file: "backups/e2e/users/a.json", line: 1, text: line },
        { file: "test/seed.json", line: 1, text: line },
        { file: "test/deep/seed.json", line: 1, text: line },
      ],
      template,
    ),
    [{ file: "test/deep/seed.json", line: 1, kind: "email" }],
  );
});

test("the follow-up names where and what kind, never the value", () => {
  const value = email("ana", "corp-fixture.io");
  const text = writtenPiiFollowup(findAddedPii([{ file: "src/a.ts", line: 1, text: value }], DEFAULT));
  assert.match(text, /src\/a\.ts:1 \(email\)/);
  assert.doesNotMatch(text, new RegExp(value.replace(".", "\\.")));
});
