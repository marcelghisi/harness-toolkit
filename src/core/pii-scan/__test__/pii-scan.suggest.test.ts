import assert from "node:assert/strict";
import { test } from "node:test";
import { isSchemaFile, suggestPiiTemplate } from "../pii-scan.suggest.ts";

test("schema files are read, data and dependencies are not", () => {
  for (const path of [
    "db/migrations/001_users.sql",
    "prisma/schema.prisma",
    "src/user.schema.ts",
    "src/schema.mjs",
    "src/models.cts",
    "openapi.yaml",
  ]) {
    assert.equal(isSchemaFile(path), true, path);
  }
  for (const path of ["node_modules/x/schema.ts", "src/app.ts", "logs/app.log", "exports/users.csv"]) {
    assert.equal(isSchemaFile(path), false, path);
  }
});

test("columns and properties propose the packs that name them and custom fields for the rest", () => {
  const suggestion = suggestPiiTemplate(
    [
      {
        path: "db/migrations/001.sql",
        text: "CREATE TABLE customers (\n  id uuid,\n  cpf varchar(14),\n  ssn text\n);",
      },
      {
        path: "prisma/schema.prisma",
        text: "model Patient {\n  diagnosis String\n  contact_email String\n}",
      },
      {
        path: "src/user.schema.ts",
        text: "const User = z.object({ cliente_nome: z.string(), project_name: z.string() })",
      },
    ],
    ["locales/pt-BR.json", "locales/es.json"],
  );
  for (const pack of ["id:br", "id:us", "domain:health", "lang:pt", "lang:es"]) {
    assert.ok(suggestion.template.extends.includes(pack), pack);
  }
  assert.deepEqual(suggestion.template.fields, ["cliente_nome", "contact_email"]);
  assert.ok(
    suggestion.evidence.some((item) => item.name === "cpf" && item.files.includes("db/migrations/001.sql")),
  );
});

// hazard: measured on a real project — Cognito keys in a SAM template proposed the health pack and four fields.
test("an infrastructure template contributes only the attributes it declares for a table", () => {
  const suggestion = suggestPiiTemplate([
    {
      path: "infra/template.yaml",
      text: "Conditions:\n  IsProd: true\nEmailMessage: hi\nCondition: IsProd\nAttributeDefinitions:\n  - AttributeName: customer_email",
    },
  ]);
  assert.equal(suggestion.template.extends.includes("domain:health"), false);
  assert.deepEqual(suggestion.template.fields, ["customer_email"]);
});
