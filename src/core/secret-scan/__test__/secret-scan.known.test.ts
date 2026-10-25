import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { loadKnownSecrets } from "../secret-scan.known.ts";
import { scanForSecrets } from "../secret-scan.service.ts";

const roots: string[] = [];

function project(files: Record<string, string> = {}): string {
  const root = mkdtempSync(join(tmpdir(), "tlc-known-secrets-"));
  roots.push(root);
  for (const [name, text] of Object.entries(files)) {
    writeFileSync(join(root, name), text);
  }
  return root;
}

afterEach(() => {
  while (roots.length > 0) {
    rmSync(roots.pop() as string, { recursive: true, force: true });
  }
});

function values(root: string, env: NodeJS.ProcessEnv = {}): string[] {
  return loadKnownSecrets(root, env).map((secret) => secret.value);
}

test("sensitive-named variables are known; ordinary ones, pointers and the shell's PWD are not", () => {
  const env = {
    DB_PASSWORD: "hunter2-dev",
    EMPRESA_LLM_API_KEY: "sk-local-0123456789",
    NODE_ENV: "development",
    PWD: "/home/me/project",
    SSH_AUTH_SOCK: "/tmp/ssh-agent.sock",
    TOKEN_URL: "https://auth.example.com/token",
    GOOGLE_APPLICATION_CREDENTIALS: "/home/me/key.json",
  };
  assert.deepEqual(values(project(), env).sort(), ["hunter2-dev", "sk-local-0123456789"]);
});

test(".env files are read with quotes, export and inline comments; templates are not", () => {
  const root = project({
    ".env": 'export DB_PASSWORD="S3nh4 F0rt3!"\nAPI_TOKEN=abc123xyz # rotated monthly\nPORT=3000\n',
    ".env.local": "CLIENT_SECRET='Xk9#mP2$vL8@qR4'\n",
    ".env.example": "DB_PASSWORD=change-me-please\n",
  });
  assert.deepEqual(values(root).sort(), ["S3nh4 F0rt3!", "Xk9#mP2$vL8@qR4", "abc123xyz"]);
});

test("a connection string's password is known whatever the variable is called", () => {
  const root = project({ ".env": "DATABASE_URL=postgres://app:S3nh4F0rt3@db:5432/app\n" });
  assert.deepEqual(values(root), ["S3nh4F0rt3"]);
});

test("values shorter than the floor, and duplicates, are dropped", () => {
  const env = { A_TOKEN: "abc", B_SECRET: "same-value-1", C_SECRET: "same-value-1" };
  assert.deepEqual(values(project(), env), ["same-value-1"]);
});

test("a known value is masked where neither a signature nor entropy would see it", () => {
  const known = loadKnownSecrets(
    project({ ".env": "DB_PASSWORD=hunter2!\nAPP_SECRET=correct-horse-battery\n" }),
    {},
  );
  const text =
    "INFO connect password=hunter2! then passphrase correct-horse-battery, commit 3f9a1c2b7d4e5f60";
  const kinds = scanForSecrets(text, known).map((match) => [text.slice(match.start, match.end), match.kind]);
  assert.deepEqual(kinds, [
    ["hunter2!", "env:DB_PASSWORD"],
    ["correct-horse-battery", "env:APP_SECRET"],
  ]);
});

test("a longer known value containing a shorter one is masked whole, and a signature inside it is not doubled", () => {
  const token = `ghp_${"aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"}`;
  const known = [
    { name: "SHORT_SECRET", value: "aB3dE5fG" },
    { name: "GITHUB_TOKEN", value: token },
  ];
  const matches = scanForSecrets(`token=${token}`, known);
  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.kind, "env:GITHUB_TOKEN");
});
