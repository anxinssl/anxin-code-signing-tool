import assert from "node:assert/strict";
import test from "node:test";
import { readVerifiedPayloads } from "../../tools/release/release-package-evidence.mjs";

function receipt(workerHash = "B".repeat(64)) {
  return {
    success: true,
    staging: {
      files: [
        { relativePath: "CodeSigner.App.exe", size: 123, sha256: "A".repeat(64) },
        { relativePath: "CodeSigner.Worker.exe", size: 456, sha256: workerHash },
        { relativePath: "THIRD-PARTY-NOTICES.txt", size: 789, sha256: "D".repeat(64) },
      ],
    },
    extractedMsiPayloads: {
      files: [
        { fileName: "CodeSigner.App.exe", size: 123, sha256: "A".repeat(64) },
        { fileName: "CodeSigner.Worker.exe", size: 456, sha256: "B".repeat(64) },
        { fileName: "THIRD-PARTY-NOTICES.txt", size: 789, sha256: "D".repeat(64) },
      ],
    },
  };
}

test("release receipt hashes originate from matching staged and extracted MSI payloads", () => {
  assert.deepEqual(readVerifiedPayloads(receipt()), [
    { fileName: "CodeSigner.App.exe", bytes: 123, sha256: "a".repeat(64) },
    { fileName: "CodeSigner.Worker.exe", bytes: 456, sha256: "b".repeat(64) },
    { fileName: "THIRD-PARTY-NOTICES.txt", bytes: 789, sha256: "d".repeat(64) },
  ]);
});

test("release receipt rejects missing, modified or additional notice payloads", () => {
  const missing = receipt();
  missing.staging.files.pop();
  assert.throws(() => readVerifiedPayloads(missing), /three required/);
  const modified = receipt();
  modified.staging.files[2].sha256 = "E".repeat(64);
  assert.throws(() => readVerifiedPayloads(modified), /NOTICES.*diverge/);
  const extra = receipt();
  extra.staging.files.push({ relativePath: "extra.exe", size: 1, sha256: "A".repeat(64) });
  assert.throws(() => readVerifiedPayloads(extra), /three required/);
});

test("release receipt rejects divergent staged and extracted payload hashes", () => {
  assert.throws(
    () => readVerifiedPayloads(receipt("C".repeat(64))),
    /CodeSigner\.Worker\.exe staged and extracted MSI payloads diverge/,
  );
});
