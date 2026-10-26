import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
const root = resolve(import.meta.dirname, "../..");
const source = readFileSync(resolve(root, "packaging/nsis/installer.nsi"), "utf8");
function validate(text) {
  const failures = [];
  if (/RMDir\s+\/r\b/i.test(text) || /taskkill|KillProcess|ExecShell.*https?:/i.test(text))
    failures.push("unsafe-system-operation");
  if (!text.includes("MsiEnumRelatedProductsW") || !text.includes('SetErrorLevel 20'))
    failures.push("missing-legacy-preflight");
  if (!text.includes('RequestExecutionLevel admin') || !text.includes('SetRegView 64'))
    failures.push("installation-boundary");
  for (const file of ["CodeSigner.App.exe", "CodeSigner.Worker.exe", "LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.txt", "source-manifest.json"])
    if (!text.includes(`File "\${PAYLOAD}\\${file}"`)) failures.push(`missing:${file}`);
  if (/\bFile\s+.*(?:signtool|\.pfx|\.p12|\.msi|\.dll)/i.test(text)) failures.push("unexpected-payload");
  if (!text.includes('StrCpy $INSTDIR "$PROGRAMFILES64\\AnxinCodeSigner"')) failures.push("untrusted-install-root");
  if (!text.includes("!insertmacro CheckOwnedFiles") || !text.includes("!insertmacro AcquireMutex"))
    failures.push("missing-file-safety");
  return failures;
}
test("NSIS keeps explicit payloads, protected installation and legacy preflight", () => {
  assert.deepEqual(validate(source), []);
});
test("installer contracts reject recursive removal, missing licenses and bundled signers", () => {
  assert.ok(validate(source + '\nRMDir /r "$INSTDIR"').includes("unsafe-system-operation"));
  assert.ok(validate(source.replace('File "${PAYLOAD}\\LICENSE"', "")).includes("missing:LICENSE"));
  assert.ok(validate(source + '\nFile "signtool.exe"').includes("unexpected-payload"));
  assert.ok(validate(source.replaceAll("MsiEnumRelatedProductsW", "MsiOther")).includes("missing-legacy-preflight"));
});
test("production solution excludes WiX and repair composition uses only NSIS maintenance", () => {
  const solution = readFileSync(resolve(root, "CodeSigner.sln"), "utf8");
  assert.doesNotMatch(solution, /\.wixproj/);
  const adapters = readFileSync(resolve(root, "src/CodeSigner.App/Services/ProductionAdapters.cs"), "utf8");
  assert.match(adapters, /private readonly NsisMaintenance runner = new\(\);/);
  assert.doesNotMatch(adapters, /private readonly WorkerRepairRunner/);
});
test("source snapshot and hash verification gate installer builds", () => {
  const build = readFileSync(resolve(root, "scripts/build-nsis.ps1"), "utf8");
  assert.ok(build.indexOf("scripts/verify-source-snapshot.mjs") < build.indexOf("Checked $compiler"));
  assert.match(build, /published\.sourceFingerprint -ne \$identity\.sourceFingerprint/);
  assert.match(build, /'\/WX'/);
});
