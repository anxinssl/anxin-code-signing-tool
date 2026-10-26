import assert from "node:assert/strict";
import test from "node:test";
import { inspectFile, normalizedText, sha256 } from "../../scripts/check-public-source.mjs";

test("source scan rejects private and generated paths even if force-added", () => {
  for (const path of [".env", ".env.production", "x/secret.pfx", "x/key.pem",
    ".local/config.json", ".omo/evidence/a.json", "artifacts/a.txt", "logs/a.txt", "runtime.jsonl"]) {
    assert.notEqual(inspectFile(path, Buffer.from("synthetic")).length, 0, path);
  }
});

test("source scan detects representative synthetic credentials without printing them", () => {
  const samples = [
    ["private-key", ["-----BEGIN ", "PRIVATE KEY-----"].join("")],
    ["github-token", ["ghp_", "a".repeat(36)].join("")],
    ["aws-access-key", ["AKIA", "A".repeat(16)].join("")],
    ["cloud-api-key", ["sk-proj-", "a".repeat(40)].join("")],
    ["credential-in-url", ["https://", "user", ":", "secret", "@example.invalid"].join("")],
    ["jwt", ["eyJ" + "a".repeat(15), "eyJ" + "b".repeat(15), "c".repeat(15)].join(".")],
  ];
  for (const [rule, text] of samples) assert.ok(inspectFile("sample.txt", Buffer.from(text)).includes(rule));
});

test("binary allowlist binds path and exact bytes", () => {
  const bytes = Buffer.from([0, 1, 2]);
  const path = "tests/fixtures/generated/fixture.exe";
  const allowed = { [path]: sha256(bytes) };
  assert.deepEqual(inspectFile(path, bytes, allowed), []);
  assert.deepEqual(inspectFile(path, Buffer.from([0, 1, 3]), allowed), ["unreviewed-binary"]);
  assert.deepEqual(inspectFile("other.exe", bytes, allowed), ["unreviewed-binary"]);
});

test("non-secret source and LF/CRLF checkouts are accepted", () => {
  assert.deepEqual(inspectFile(".env.example", Buffer.from("SETTING=example")), []);
  assert.equal(sha256(normalizedText(Buffer.from("a\r\nb\r\n"))), sha256("a\nb\n"));
});
