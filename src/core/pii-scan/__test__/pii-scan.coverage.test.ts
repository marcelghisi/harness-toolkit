import assert from "node:assert/strict";
import { test } from "node:test";
import {
  describeUncovered,
  uncoveredFields,
  uncoveredFollowup,
  uncoveredInAdded,
} from "../pii-scan.coverage.ts";
import { compilePiiTemplate } from "../pii-scan.template.ts";

const ENTITY = [
  "@Entity",
  "public class Customer {",
  "  @Id private Long id;",
  "  private String fullName;",
  '  @Column(name = "mother_maiden_name") private String mother;',
  "  private String nif;",
  "  private String companyName;",
  "}",
].join("\n");

const FILE = { path: "src/main/java/app/Customer.java", text: ENTITY };

test("a personal-looking field the template does not label is reported, with the pack that would cover it", () => {
  const found = uncoveredFields([FILE], compilePiiTemplate({ extends: ["global"] }));
  assert.deepEqual(
    found.map((field) => [field.field, field.packs]),
    [
      ["mother_maiden_name", []],
      ["nif", ["id:es", "id:pt"]],
    ],
  );
  assert.match(describeUncovered(found[1] ?? { field: "", file: "", packs: [] }), /enable id:es or id:pt/);
});

test("a labelled field, a pack's field and an ignored field are covered", () => {
  const template = compilePiiTemplate({
    extends: ["global", "id:es"],
    fields: ["motherMaidenName"],
    ignore: ["company_name"],
  });
  assert.deepEqual(uncoveredFields([FILE], template), []);
});

// invariant: `ignore` only quiets the coverage check — it never unmasks a value a pack still labels.
test("an ignored field a pack labels is still in the template's labels", () => {
  const template = compilePiiTemplate({ extends: ["global"], ignore: ["email"] });
  assert.ok(template.labels.has("email"));
  assert.ok(template.ignore.has("email"));
});

test("only the turn's added lines are read, with the dialect the whole file selects", () => {
  const added = [
    { file: FILE.path, line: 5, text: '  @Column(name = "mother_maiden_name") private String mother;' },
  ];
  const found = uncoveredInAdded(added, () => ENTITY, compilePiiTemplate({ extends: ["global"] }));
  assert.deepEqual(
    found.map((field) => [field.field, field.line]),
    [["mother_maiden_name", 5]],
  );
  const plain = uncoveredInAdded(
    [{ file: "src/Mailer.java", line: 2, text: "  private String customerEmail;" }],
    () => "public class Mailer {\n  private String customerEmail;\n}",
    compilePiiTemplate({ extends: ["global"] }),
  );
  assert.deepEqual(plain, []);
});

test("the follow-up names the field and the file, and sends the agent to the skill, not the template", () => {
  const text = uncoveredFollowup([{ field: "mother_maiden_name", file: FILE.path, line: 5, packs: [] }]);
  assert.match(text, /mother_maiden_name — src\/main\/java\/app\/Customer\.java:5/);
  assert.match(text, /harness-pii/);
  assert.match(text, /Do not edit the template yourself/);
});
