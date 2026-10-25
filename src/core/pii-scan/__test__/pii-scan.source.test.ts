import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyPiiSource, type PiiSource } from "../pii-scan.source.ts";

// invariant: the local container and the remote server are one source — only the client decides.
test("a database client is a db-query wherever it runs", () => {
  const commands = [
    'psql -c "select * from users"',
    "docker compose exec db psql -U app -c 'select 1'",
    "docker exec -it pg mysql -e 'select * from users'",
    "kubectl exec deploy/api -- psql -c 'select 1'",
    "ssh prod 'mongosh --eval \"db.users.find()\"'",
    'sqlite3 fixture.db "select * from users"',
    "awslocal dynamodb scan --table-name ghifinance",
    "aws dynamodb query --table-name t",
  ];
  for (const command of commands) {
    assert.equal(classifyPiiSource({ command }), "db-query", command);
  }
});

test("HTTP clients, log readers and data files are told apart", () => {
  const cases: [string, PiiSource][] = [
    ["curl -s https://api.example.com/users", "api-response"],
    ["http GET :3000/customers", "api-response"],
    ["docker compose logs api", "log"],
    ["tail -n 50 logs/app.log", "log"],
    ["cat exports/users.csv", "data-file"],
    ["head config/app.yaml", "config-file"],
    ["ls -la", "other"],
  ];
  for (const [command, source] of cases) {
    assert.equal(classifyPiiSource({ command }), source, command);
  }
});

test("a read tool's file decides the source, and an MCP tool is a service", () => {
  assert.equal(classifyPiiSource({ toolName: "Read", filePath: "src/users.ts" }), "source-file");
  assert.equal(classifyPiiSource({ toolName: "Read", filePath: "config/app.json" }), "config-file");
  assert.equal(classifyPiiSource({ toolName: "Read", filePath: "dump/users.sql" }), "data-file");
  assert.equal(classifyPiiSource({ toolName: "Read", filePath: "logs/app.log" }), "log");
  assert.equal(classifyPiiSource({ toolName: "mcp__postgres__query" }), "db-query");
  assert.equal(classifyPiiSource({ toolName: "mcp__linear__get_issue" }), "api-response");
  assert.equal(classifyPiiSource({ toolName: "supabase_execute_sql" }), "db-query");
});
