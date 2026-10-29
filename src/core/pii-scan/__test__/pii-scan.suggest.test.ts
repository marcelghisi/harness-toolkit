import assert from "node:assert/strict";
import { test } from "node:test";
import { isSchemaCandidate, isSchemaFile, suggestPiiTemplate } from "../pii-scan.suggest.ts";

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

function proposed(path: string, text: string): string[] {
  return suggestPiiTemplate([{ path, text }]).evidence.map((item) => item.name);
}

// why: the schema of most projects lives in an ORM class, not a .sql file — each case is the idiom its framework
// documents, and each names one personal field and one that is not.
test("ORM classes and migrations in the common languages and frameworks propose their personal fields", () => {
  const cases: [string, string, string][] = [
    [
      "src/main/java/app/Customer.java",
      '@Entity\npublic class Customer {\n  @Id private Long id;\n  @Column(name = "holder_name") private String holder;\n  private String customerEmail;\n  private int retries;\n}',
      "holder_name customer_email",
    ],
    [
      "app/src/Customer.kt",
      "@Entity\ndata class Customer(val id: Long, val fullName: String, val plan: String)",
      "full_name",
    ],
    ["src/User.java", "public record User(Long id, String contactEmail, int score) {}", "contact_email"],
    [
      "Models/Customer.cs",
      'public class Customer {\n  public int Id { get; set; }\n  public string FullName { get; set; }\n  [Column("billing_phone")] public string Phone2 { get; set; }\n}',
      "full_name billing_phone",
    ],
    [
      "Migrations/20240101_Init.cs",
      "columns: table => new {\n  CustomerEmail = table.Column<string>(nullable: false)\n}",
      "customer_email",
    ],
    [
      "internal/user.go",
      'type User struct {\n  ID int `json:"id"`\n  Email string `json:"email" gorm:"column:contact_email"`\n}',
      "email contact_email",
    ],
    [
      "app/models.py",
      "class Customer(models.Model):\n    full_name = models.CharField(max_length=80)\n    plan = models.CharField()",
      "full_name",
    ],
    [
      "app/db.py",
      "class User(Base):\n    customer_email: Mapped[str] = mapped_column(String)\n    tier = Column(Integer)",
      "customer_email",
    ],
    ["app/api.py", "class Signup(BaseModel):\n    contact_phone: str\n    plan: str", "contact_phone"],
    [
      "alembic/versions/01_init.py",
      "op.create_table('users', sa.Column('customer_email', sa.String()))",
      "customer_email",
    ],
    [
      "db/schema.rb",
      'create_table "users" do |t|\n  t.string "full_name"\n  t.integer "plan"\nend',
      "full_name",
    ],
    ["db/migrate/02_add.rb", "add_column :users, :contact_phone, :string", "contact_phone"],
    [
      "database/migrations/2024_create.php",
      "Schema::create('users', function (Blueprint $table) {\n  $table->string('customer_email');\n});",
      "customer_email",
    ],
    [
      "lib/app/user.ex",
      'schema "users" do\n  field :full_name, :string\n  field :tier, :integer\nend',
      "full_name",
    ],
    [
      "src/user.entity.ts",
      "@Entity()\nexport class User {\n  @Column() customerEmail: string;\n}",
      "customer_email",
    ],
    [
      "src/db/tables.ts",
      'export const users = pgTable("users", { id: serial("id"), phone: text("contact_phone") });',
      "contact_phone",
    ],
    [
      "migrations/01.js",
      "exports.up = (knex) => knex.schema.createTable('users', (t) => { t.string('customer_email'); });",
      "customer_email",
    ],
    ["proto/user.proto", "message User {\n  string full_name = 1;\n  int32 tier = 2;\n}", "full_name"],
    [
      "schemas/user.avsc",
      '{"type":"record","fields":[{"name":"customer_email","type":"string"}]}',
      "customer_email",
    ],
    [
      "db/changelog-master.xml",
      '<createTable tableName="users"><column name="full_name" type="varchar"/></createTable>',
      "full_name",
    ],
  ];
  for (const [path, text, expected] of cases) {
    const names = proposed(path, text);
    for (const field of expected.split(" ")) {
      assert.ok(names.includes(field), `${path}: ${field} in ${names.join(",")}`);
    }
  }
});

// invariant: an ordinary source file opens no pattern — the marker is what makes a class a schema.
test("a source file with no ORM marker and no schema name proposes nothing", () => {
  assert.deepEqual(
    proposed("src/main/java/app/Mailer.java", "public class Mailer {\n  private String customerEmail;\n}"),
    [],
  );
  assert.deepEqual(proposed("pkg/notify.go", "type Note struct {\n  Email string\n}"), []);
  assert.deepEqual(proposed("src/util.kt", "fun f() { val fullName: String = x }"), []);
});

test("data directories are never opened, vendored code is never opened", () => {
  assert.equal(isSchemaCandidate("src/fixtures/users.ts"), false);
  assert.equal(isSchemaCandidate("db/seeds/users.rb"), false);
  assert.equal(isSchemaCandidate("vendor/lib/Model.php"), false);
  assert.equal(isSchemaCandidate("src/main/java/app/Customer.java"), true);
});

test("a candidate a reader judged personal is kept even with no personal word in its name", () => {
  const suggestion = suggestPiiTemplate(
    [],
    [],
    [
      { name: "titularConta", evidence: "Conta.java: holder of the account" },
      { name: "parecerTecnico", kind: "health-note", mode: "mask" },
      { name: "cpf" },
    ],
  );
  assert.deepEqual(suggestion.template.fields, [
    { name: "parecer_tecnico", kind: "health-note", mode: "mask" },
    "titular_conta",
  ]);
  assert.ok(suggestion.template.extends.includes("id:br"));
  assert.ok(
    suggestion.evidence.some((item) => item.files.includes("candidate: Conta.java: holder of the account")),
  );
});
