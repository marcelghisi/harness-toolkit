---
name: harness-pii
description: Interactive wizard that proposes this project's PII template (.tlc/harness/pii.json) by reading its domain model in any language — JPA/Hibernate, Kotlin, EF Core, GORM, Django, SQLAlchemy, Pydantic, Rails, Laravel/Doctrine, Ecto, TypeORM, Prisma, Drizzle, Sequelize, Mongoose, migrations, Protobuf, Avro, OpenAPI — then validates the proposal with `tlc harness pii suggest --candidates` and calibrates it with `tlc harness pii test`. Use when the user says set up PII, configure the PII template, pii.json, which fields are personal data, calibrate PII masking, too much or too little is being pseudonymised, or after adding entities with personal data. Do NOT use to read, unmask or export personal data, to turn PII protection off, or for the first harness setup (that is harness-init, which hands off here).
license: CC-BY-4.0
metadata:
  author: Marcel Ghisi
  version: 1.0.0
---

# Harness PII (project template wizard)

Propose what counts as personal data **in this project**, so the harness pseudonymises it in tool output and
refuses it in written code. The operator reviews and saves the result: `.tlc/harness/pii.json` is policy, and the
floor denies every agent write to it. Do not try another route to write it — hand the file to the operator.

Concepts: `tlc harness help` and `docs/concepts.md` (PII section). The CLI does the mechanical part and is the only
thing that may turn names into a template; this skill does the reading and the judgement.

## Rules for the whole session

- **Read code and schema, never data.** Do not open seeds, fixtures, dumps, exports, `data/`, `.db`/`.sqlite`
  files, CSV/JSON payloads, logs or `.env`. Field **names** are what you need; no value is.
- **Never run a query or call an API to "see what the data looks like".** If the operator wants calibration
  against real output, they run `tlc harness pii test` themselves (step 6).
- **Never write `.tlc/harness/pii.json`**, `config.json` or anything under `.tlc/harness/`. Print the proposal.
- Personal data is about **a person**: a customer, patient, employee, user, holder, contact. A company's,
  a product's or a resource's attribute is not, even when it is called `name` or `email`.
- Credentials (`password`, `token`, `api_key`, `secret`) are not PII — secret hygiene already covers them. Do not
  add them as fields.

## Instructions

### Step 1: Preconditions

1. Run `tlc harness doctor` and read the `pii template` row: is there a template, which packs, any errors?
2. If `.tlc/harness/pii.json` exists, read it — it is the starting point, not something to replace wholesale.
   If an example sits elsewhere in the repo (`pii.example.json`), read it too and say which you are using.

### Step 2: Ask what only the operator knows (one message, all at once)

- **Where are the people this system stores?** Countries or regions → `id:` packs (`id:br`, `id:us`, `id:es`,
  `id:pt`, `id:fr`, `id:de`, `id:it`, `id:mx`, `id:ar`, `id:in`, `id:ca`, `id:au`, `id:uk`).
- **Which languages are the field names and the product in?** → `lang:` packs (`pt`, `es`, `fr`, `de`, `it`;
  English is always included).
- **Which sector?** → `domain:finance`, `domain:hr`, `domain:health`, `domain:special` (GDPR art. 9 / LGPD
  sensitive data: health, religion, ethnicity, orientation, biometrics — fully masked, no attribute kept).
- **Test data conventions:** fixture e-mail domains (beyond `example.*`, `*.test`, `*.invalid`) and seed/fixture
  paths that may legitimately hold sample people → `fixtures.domains`, `fixtures.paths`.

Propose a default for each from the repository (locale files, currency, README) so the operator can just confirm.

### Step 3: Let the CLI read what it can

Run `tlc harness pii suggest --json`. It reads SQL and migrations, Prisma, GraphQL, OpenAPI, Protobuf, Avro,
Liquibase and ORM classes in Java/Kotlin/Scala, C#, Go, Python, Ruby, PHP, Elixir and TypeScript/JavaScript.
Keep its `evidence` — it is what you will show the operator.

### Step 4: Read the domain model the CLI could not, or could not judge

Find the entity, model, DTO and API-contract definitions (search for the ORM's markers: `@Entity`, `models.Model`,
`DbSet<`, `gorm`, `schema "`, `create_table`, `pgTable(`, `z.object(`, `message `…). For each class that describes
a **person or something a person owns** (account, address, order, ticket, appointment), list the fields that
identify or describe that person:

- direct identifiers: names, e-mails, phones, documents, account and card numbers, addresses, birth dates, IPs,
  device IDs, usernames when they are real-world handles;
- free-text fields a person writes (`message`, `notes`, `comment`, `bio`) — propose `mode: "mask"`, since there
  is no shape to pseudonymise;
- sensitive-category fields (diagnosis, religion, ethnicity…) — propose `mode: "mask"` and `domain:special` or
  `domain:health`.

Use the name **as it appears in output** (the column or JSON key), not only the property: `@Column(name =
"holder_name") String holder` is `holder_name`. Skip foreign keys and surrogate IDs (`customer_id`), timestamps,
statuses and enums.

### Step 5: Validate through the CLI

Write the candidates to a scratch file outside the repository (or pipe them), one entry per field:

```json
[
  { "name": "holder_name", "evidence": "PaymentMethod.java:@Column(name=holder_name)" },
  { "name": "message", "mode": "mask", "evidence": "SupportTicket.kt: free text written by the customer" }
]
```

Run `tlc harness pii suggest --candidates <file> --json`. The CLI normalises names, drops what a pack already
covers, maps known names to packs, and ignores anything in the input other than `name`, `kind`, `mode` and
`evidence`. Then merge in the packs from step 2 and the fixtures, and run the result through the same command once
more if you changed names, so what you hand over is what the CLI produced.

### Step 6: Present, then hand over

Show the operator:

1. the proposed `pii.json`, complete;
2. a table: field → why (the evidence) → pack or custom field → mode;
3. what you deliberately left out and why (credentials, IDs, company attributes);
4. what to do next, in their own terminal:
   - save the file as `.tlc/harness/pii.json` and commit it, so it is reviewed like any other policy;
   - `tlc harness doctor` — the `pii template` row must show no errors;
   - `tlc harness pii test <sample output file>` on a real query result or API response they captured — it prints
     positions and kinds only, never values — and tell you what was over- or under-masked.

If they report a miss or a false positive, adjust the candidates and repeat step 5. Never ask them to paste the
raw values.

## Troubleshooting

- **The CLI found nothing:** the project has no schema in a form it reads — step 4 carries the whole proposal.
- **A non-personal value is pseudonymised** (a package name, a resource name): note the field and the value's
  *shape* (not the value) for the harness maintainers; do not add an exclusion pattern to work around it.
- **The operator wants PII protection off:** that is `pii.redactOutput` / `pii.blockWrites` in
  `.tlc/harness/config.json`, the operator's decision, recorded at session start. Explain the trade-off; do not edit it.
