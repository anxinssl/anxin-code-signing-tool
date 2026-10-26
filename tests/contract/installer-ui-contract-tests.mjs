import assert from "node:assert/strict";
import {
  appendFileSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const project = join(
  root,
  "tools",
  "installer-verifier",
  "CodeSigner.InstallerVerifier.csproj",
);
const packagePath = join(root, "packaging", "msi", "Package.wxs");
const msiPath = process.env.CODESIGNER_INSTALLER_TEST_MSI === undefined
  ? join(root, "packaging", "msi", "bin", "x64", "Release", "CodeSigner.Installer.msi")
  : resolve(process.env.CODESIGNER_INSTALLER_TEST_MSI);
const settingsPath = join(root, "src", "CodeSigner.App", "SettingsWindow.xaml.cs");
const stagingPath = join(root, "artifacts", "staging");
const wixToolsetDllPath = process.env.CODESIGNER_WIX_TOOLSET_DLL === undefined
  ? join(
      homedir(),
      ".nuget",
      "packages",
      "wixtoolset.sdk",
      "6.0.2",
      "tools",
      "net6.0",
      "wix.dll",
    )
  : resolve(process.env.CODESIGNER_WIX_TOOLSET_DLL);
const receiptDirectory = process.env.CODESIGNER_INSTALLER_TEST_RECEIPT_DIR;
const expectedProductVersion = "1.0.40";
const expectedProductCode = "{C5A22B2A-C390-4AA3-AD3C-F462BE0AD73C}";
const expectedUpgradeCode = "{C81BF087-67D0-41F3-8581-9E773813118B}";
const requiredPayloads = ["CodeSigner.App.exe", "CodeSigner.Worker.exe", "THIRD-PARTY-NOTICES.txt"];
const forbiddenStagedPayloads = [
  { label: "SDK directory", relativePath: "sdk/sdk-helper.dll" },
  { label: "SignTool executable", relativePath: "signtool.exe" },
  { label: "Windows Kits hierarchy", relativePath: "Windows Kits/10/bin/10.0.26100.0/x64/tool.exe" },
  { label: "third-party signer", relativePath: "third-party-signer.exe" },
];
const fontStyleId = "CodeSigner_Font_Normal";
const fontFaceName = "Microsoft YaHei UI";
const canonicalFontStyle = `      <TextStyle Id="${fontStyleId}" FaceName="${fontFaceName}" Size="9" />`;
const canonicalFontProperty = `    <Property Id="DefaultUIFont" Value="${fontStyleId}" />`;

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex").toUpperCase();
}

function runVerifier(sourcePath, candidatePath = msiPath) {
  const result = spawnSync(
    "dotnet",
    [
      "run",
      "--project",
      project,
      "-c",
      "Release",
      "--",
      "--source",
      sourcePath,
      "--settings-source",
      settingsPath,
      "--msi",
      candidatePath,
    ],
    { cwd: root, encoding: "utf8", windowsHide: true },
  );
  result.evidenceBinding = {
    sourcePath: resolve(sourcePath),
    sourceSha256: sha256File(sourcePath),
    compiledInputPath: resolve(candidatePath),
  };
  return result;
}

function runPackageVerifier(
  sourcePath = packagePath,
  candidatePath = msiPath,
  payloadPath = stagingPath,
) {
  const result = spawnSync(
    "dotnet",
    [
      "run",
      "--project",
      project,
      "-c",
      "Release",
      "--",
      "--source",
      sourcePath,
      "--settings-source",
      settingsPath,
      "--staging",
      payloadPath,
      "--msi",
      candidatePath,
      "--wix-toolset-dll",
      wixToolsetDllPath,
      "--expected-version",
      expectedProductVersion,
      "--expected-product-code",
      expectedProductCode,
      "--expected-upgrade-code",
      expectedUpgradeCode,
    ],
    { cwd: root, encoding: "utf8", windowsHide: true },
  );
  result.evidenceBinding = {
    sourcePath: resolve(sourcePath),
    sourceSha256: sha256File(sourcePath),
    stagingPath: resolve(payloadPath),
    compiledInputPath: resolve(candidatePath),
    wixToolsetDllPath: resolve(wixToolsetDllPath),
    wixToolsetDllSha256: sha256File(wixToolsetDllPath),
  };
  return result;
}

function replaceExact(source, before, after, expectedCount) {
  const pieces = source.split(before);
  assert.equal(
    pieces.length - 1,
    expectedCount,
    `fixture mutation expected ${expectedCount} exact occurrences`,
  );
  return pieces.join(after);
}

function withCanonicalFontContract(source) {
  const withoutStyle = source.replace(
    /^[ \t]*<TextStyle\b(?=[^>\r\n]*\bId="CodeSigner_Font_Normal")[^>\r\n]*\/>[ \t]*\r?\n/gm,
    "",
  );
  const withoutProperty = withoutStyle.replace(
    /^[ \t]*<Property\b(?=[^>\r\n]*\bId="DefaultUIFont")[^>\r\n]*\/>[ \t]*\r?\n/gm,
    "",
  );
  const marker = '    <Property Id="WIXUI_INSTALLDIR" Value="INSTALLFOLDER" />';
  return replaceExact(
    replaceExact(withoutProperty, marker, [marker, canonicalFontProperty].join("\n"), 1),
    "    <UI>",
    ["    <UI>", canonicalFontStyle].join("\n"),
    1,
  );
}

function withFixture(t, mutate) {
  const directory = mkdtempSync(join(tmpdir(), "codesigner-installer-ui-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const fixturePath = join(directory, "Package.wxs");
  const source = readFileSync(packagePath, "utf8").replaceAll("\r\n", "\n");
  writeFileSync(fixturePath, mutate(source), "utf8");
  return fixturePath;
}

function withStagingFixture(t, forbiddenRelativePath) {
  const directory = mkdtempSync(join(tmpdir(), "codesigner-package-closure-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const payload of requiredPayloads) {
    writeFileSync(join(directory, payload), `fixture:${payload}\n`, "utf8");
  }
  const forbiddenPath = join(directory, ...forbiddenRelativePath.split("/"));
  mkdirSync(dirname(forbiddenPath), { recursive: true });
  writeFileSync(forbiddenPath, `forbidden:${forbiddenRelativePath}\n`, "utf8");
  return directory;
}

function withStagingHashMismatchFixture(t, payloadName = "CodeSigner.App.exe") {
  const directory = mkdtempSync(join(tmpdir(), "codesigner-package-hash-mismatch-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const payload of requiredPayloads) {
    copyFileSync(join(stagingPath, payload), join(directory, payload));
  }
  appendFileSync(join(directory, payloadName), Buffer.from([0x00]));
  return directory;
}

function injectAuthoredPayload(source, relativePath) {
  const appFile = '          <File Source="../../artifacts/staging/CodeSigner.App.exe" KeyPath="yes" />';
  const injected = `          <File Source="../../artifacts/staging/${relativePath}" />`;
  return replaceExact(source, appFile, `${appFile}\n${injected}`, 1);
}

function recordReceipt(fileName, receipt) {
  if (receiptDirectory === undefined) {
    return;
  }
  mkdirSync(receiptDirectory, { recursive: true });
  writeFileSync(
    join(receiptDirectory, fileName),
    `${JSON.stringify(receipt, null, 2)}\n`,
    "utf8",
  );
}

function parseVerifierReceipt(result) {
  return {
    ...JSON.parse(result.stdout),
    evidenceBinding: result.evidenceBinding,
  };
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function dialogBlock(source, dialogId) {
  const pattern = new RegExp(
    `<Dialog\\b(?=[^>]*\\bId="${escapeRegExp(dialogId)}"[^>]*)[^>]*>[\\s\\S]*?</Dialog>`,
    "g",
  );
  const matches = [...source.matchAll(pattern)];
  assert.equal(
    matches.length,
    1,
    `fixture mutation expected one ${dialogId} dialog`,
  );
  return {
    start: matches[0].index,
    end: matches[0].index + matches[0][0].length,
    text: matches[0][0],
  };
}

function controlBlock(source, controlId) {
  const pattern = new RegExp(
    `<Control\\b(?=[^>]*\\bId="${escapeRegExp(controlId)}"[^>]*)[^>]*>`,
    "g",
  );
  const matches = [...source.matchAll(pattern)];
  assert.equal(
    matches.length,
    1,
    `fixture mutation expected one ${controlId} control opening`,
  );
  const start = matches[0].index;
  const opening = matches[0][0];
  const openingEnd = start + opening.length;
  const close = source.indexOf("</Control>", openingEnd);
  const end = opening.endsWith("/>")
    ? openingEnd
    : close >= 0
      ? close + "</Control>".length
      : source.indexOf("/>", openingEnd) + 2;
  assert.ok(end > start, `fixture mutation could not bound ${controlId}`);
  return { start, end, text: source.slice(start, end) };
}

function mutateControl(source, controlId, mutate) {
  const block = controlBlock(source, controlId);
  const replacement = mutate(block.text);
  assert.notEqual(replacement, block.text, `${controlId} fixture mutation was a no-op`);
  return source.slice(0, block.start) + replacement + source.slice(block.end);
}

function mutateDialogControl(source, dialogId, controlId, mutate) {
  const dialog = dialogBlock(source, dialogId);
  const replacement = mutateControl(dialog.text, controlId, mutate);
  return source.slice(0, dialog.start) + replacement + source.slice(dialog.end);
}

function removeDialogControl(source, dialogId, controlId) {
  const dialog = dialogBlock(source, dialogId);
  const control = controlBlock(dialog.text, controlId);
  const replacement = dialog.text.slice(0, control.start) + dialog.text.slice(control.end);
  return source.slice(0, dialog.start) + replacement + source.slice(dialog.end);
}

function removeDialogSubscription(source, dialogId, controlId) {
  return mutateDialogControl(source, dialogId, controlId, (control) => {
    const pattern = /\s*<Subscribe\b[^>]*\/>/;
    assert.match(control, pattern, `${dialogId}.${controlId} must expose a Subscribe row`);
    return control.replace(pattern, "");
  });
}

function mutateFirstPublishBlock(block, controlId) {
  return mutateControl(block, controlId, (control) => {
    const publishes = [...control.matchAll(/<Publish\b[^>]*\/>/g)];
    assert.ok(publishes.length > 0, `${controlId} must expose a Publish row`);
    const target = publishes[0][0];
    const mutated = target.includes('Event="')
      ? target.replace(/Event="[^"]+"/, 'Event="BrokenEvent"')
      : target.replace(/Property="[^"]+"/, 'Property="BrokenProperty"');
    assert.notEqual(mutated, target, `${controlId} Publish event was not found`);
    return control.replace(target, mutated);
  });
}

function mutateFirstPublish(source, dialogId, controlId) {
  return mutateDialogControl(source, dialogId, controlId, (block) => {
    return mutateFirstPublishBlock(block, controlId);
  });
}

function mutateControlAttribute(source, controlId, attribute, from, to) {
  return mutateControl(source, controlId, (block) =>
    replaceExact(block, `${attribute}="${from}"`, `${attribute}="${to}"`, 1),
  );
}

function driftDialogControlAttribute(source, dialogId, controlId, attribute, delta) {
  return mutateDialogControl(source, dialogId, controlId, (control) => {
    const pattern = new RegExp(`(${escapeRegExp(attribute)}=")([0-9]+)(")`);
    const match = control.match(pattern);
    assert.ok(match, `${dialogId}.${controlId} must expose numeric ${attribute}`);
    return control.replace(pattern, `$1${Number(match[2]) + delta}$3`);
  });
}

function mutateDialogId(source, dialogId, replacement) {
  return replaceExact(
    source,
    `<Dialog Id="${dialogId}"`,
    `<Dialog Id="${replacement}"`,
    1,
  );
}

function setDialogShellGeometry(source, width, height) {
  let mutated = source;
  for (const dialogId of [
    "WelcomeDlg",
    "InstallDirectoryDlg",
    "BrowseDlg",
    "InstallProgressDlg",
    "ExitDialog",
    "UninstallProgressDlg",
  ]) {
    const dialog = dialogBlock(mutated, dialogId);
    const openingEnd = dialog.text.indexOf(">");
    assert.ok(openingEnd > 0, `${dialogId} opening tag must be present`);
    const opening = dialog.text.slice(0, openingEnd + 1);
    const withWidth = opening.replace(/\bWidth="[0-9]+"/, `Width="${width}"`);
    const withGeometry = withWidth.replace(/\bHeight="[0-9]+"/, `Height="${height}"`);
    const replacement = withGeometry + dialog.text.slice(openingEnd + 1);
    mutated = mutated.slice(0, dialog.start) + replacement + mutated.slice(dialog.end);
  }
  return mutated;
}

let compiledSnapshot;

function readCompiledSnapshot() {
  if (compiledSnapshot === undefined) {
    const result = runVerifier(packagePath);
    assert.ok(result.status === 0 || result.status === 1, result.stdout + result.stderr);
    const receipt = JSON.parse(result.stdout);
    assert.notEqual(receipt.msi, null, "compiled MSI snapshot is mandatory for table fixtures");
    compiledSnapshot = receipt.msi;
  }
  return structuredClone(compiledSnapshot);
}

function withCompiledTableFixture(t, mutate) {
  const directory = mkdtempSync(join(tmpdir(), "codesigner-installer-msi-tables-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const snapshot = readCompiledSnapshot();
  const fixture = {
    schema: "codesigner-compiled-msi-table-fixture-v1",
    sourceMsiPath: snapshot.path,
    sourceMsiSha256: snapshot.sha256,
    tables: snapshot.tables,
  };
  mutate(fixture);
  const fixturePath = join(directory, "compiled-msi-tables.json");
  writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`, "utf8");
  return fixturePath;
}

function setCanonicalCompiledFontContract({ tables }) {
  tables.TextStyle = [
    {
      fields: {
        TextStyle: fontStyleId,
        FaceName: fontFaceName,
        Size: "9",
        Color: "",
        StyleBits: "0",
      },
    },
  ];
  tables.Property = tables.Property.filter(({ fields }) =>
    fields.Property !== "DefaultUIFont"
  );
  tables.Property.push({
    fields: {
      Property: "DefaultUIFont",
      Value: fontStyleId,
    },
  });
}

function withFontVerificationFixture(t, mutateSource, mutateTables) {
  const sourcePath = withFixture(t, (source) => {
    const canonical = withCanonicalFontContract(source);
    return mutateSource === undefined ? canonical : mutateSource(canonical);
  });
  const compiledPath = withCompiledTableFixture(t, (fixture) => {
    setCanonicalCompiledFontContract(fixture);
    if (mutateTables !== undefined) {
      mutateTables(fixture);
    }
  });
  return { sourcePath, compiledPath };
}

function singleTableRow(fixture, table, predicate, description) {
  const matches = fixture.tables[table].filter(({ fields }) => predicate(fields));
  assert.equal(matches.length, 1, `expected one compiled ${description} row`);
  return matches[0].fields;
}

function mutatePublishValue(source, dialogId, controlId, value, replacement) {
  return mutateDialogControl(source, dialogId, controlId, (block) => {
    const pattern = new RegExp(
      `(<Publish\\b[^>]*\\bValue=")${escapeRegExp(value)}("[^>]*/>)`,
    );
    const match = block.match(pattern);
    assert.ok(match, `${dialogId}.${controlId} must publish ${value}`);
    return block.replace(pattern, `$1${replacement}$2`);
  });
}

function injectExecuteSequenceDialogAction(source, dialogId) {
  const pattern = /\r?\n(\s*)<\/InstallExecuteSequence>/;
  const match = source.match(pattern);
  assert.ok(match, "InstallExecuteSequence closing element must be present");
  const indentation = match[1];
  const action = `${indentation}  <Custom Action="${dialogId}" After="InstallFiles" Condition="1" />`;
  return source.replace(pattern, `\n${action}\n${indentation}</InstallExecuteSequence>`);
}

function assertRejectedWith(result, receiptName, fragments) {
  assertRejectedWithAll(result, receiptName, [fragments]);
}

function assertRejectedWithAll(result, receiptName, fragmentGroups) {
  assert.equal(result.status, 1, result.stdout + result.stderr);
  const receipt = parseVerifierReceipt(result);
  recordReceipt(receiptName, receipt);
  for (const fragments of fragmentGroups) {
    assert.ok(
      receipt.violations.some((violation) =>
        fragments.every((fragment) => violation.includes(fragment)),
      ),
      `${fragments.join(" + ")} was not reported:\n${result.stdout}`,
    );
  }
}

function nonFontViolations(receipt) {
  const prefixes = [
    "Authoring font contract",
    "Authoring TextStyle",
    "Authoring Property DefaultUIFont",
    "MSI font contract",
    "MSI TextStyle",
    "MSI Property DefaultUIFont",
  ];
  return receipt.violations.filter((violation) =>
    !prefixes.some((prefix) => violation.startsWith(prefix))
  );
}

test("Installer metadata describes all supported signing families without EXE-only copy", () => {
  const source = readFileSync(packagePath, "utf8");
  assert.match(
    source,
    /<SummaryInformation Description="安信证书签名工具 - 支持 PE、Windows 安装包、CAB\/CAT、AppX\/MSIX 与脚本签名" \/>/,
  );
  assert.match(
    source,
    /<Property Id="ARPCOMMENTS" Value="支持 PE、Windows 安装包、CAB\/CAT、AppX\/MSIX 与脚本签名的安信证书签名工具" \/>/,
  );
  assert.doesNotMatch(source, /用于 \.exe 文件|\.exe 代码签名工具/);
});

test("Given current release artifacts, when package closure is verified, then only App and Worker ship", () => {
  const result = runPackageVerifier();
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const receipt = parseVerifierReceipt(result);
  recordReceipt("package-closure-positive.json", receipt);
  assert.equal(receipt.success, true);
  assert.deepEqual(receipt.violations, []);
  assert.deepEqual(receipt.packageClosure.requiredPayloads, requiredPayloads);
  assert.deepEqual(receipt.packageClosure.forbiddenPayloads, []);
  assert.equal(receipt.packageClosure.authoringFileCount, requiredPayloads.length);
  assert.equal(receipt.packageClosure.stagedFileCount, requiredPayloads.length);
  assert.equal(receipt.packageClosure.msiFileCount, requiredPayloads.length);
  assert.equal(receipt.packageClosure.extractedMsiPayloadCount, requiredPayloads.length);
  assert.equal(receipt.packageClosure.stagedPayloadHashesMatch, true);
  assert.equal(receipt.packageClosure.sipBridgeDeployment, "compiled-worker-command");
  assert.equal(receipt.packageClosure.externalSipBridgePayloadRequired, false);
  assert.equal(receipt.expectedIdentity.productVersion, expectedProductVersion);
  assert.equal(receipt.expectedIdentity.productCode, expectedProductCode);
  assert.equal(receipt.expectedIdentity.upgradeCode, expectedUpgradeCode);
  assert.equal(receipt.extractedMsiPayloads.extractionMethod, "wix-msi-decompile-x");
  assert.equal(receipt.extractedMsiPayloads.temporaryDirectoryRemoved, true);
  assert.deepEqual(
    receipt.extractedMsiPayloads.files.map(({ fileName }) => fileName),
    requiredPayloads,
  );
  for (const payload of requiredPayloads) {
    const staged = receipt.staging.files.find(({ relativePath }) => relativePath === payload);
    const extracted = receipt.extractedMsiPayloads.files.find(({ fileName }) => fileName === payload);
    assert.equal(extracted.size, staged.size);
    assert.equal(extracted.sha256, staged.sha256);
  }
});

test("Given staged bytes that differ from the embedded MSI payload, when package closure is verified, then the hash mismatch is rejected", (t) => {
  const payloadPath = withStagingHashMismatchFixture(t);
  const result = runPackageVerifier(packagePath, msiPath, payloadPath);
  assertRejectedWith(result, "negative-extracted-payload-hash-mismatch.json", [
    "Extracted MSI payload",
    "CodeSigner.App.exe",
    "must match staged bytes",
  ]);
});

test("third-party notices cannot be omitted from installer source", (t) => {
  const fixture = withFixture(t, (source) => replaceExact(source,
    '          <File Source="../../artifacts/staging/THIRD-PARTY-NOTICES.txt" KeyPath="yes" />',
    "", 1));
  assertRejectedWith(runVerifier(fixture), "negative-missing-notices.json", [
    "NoticesComponent", "THIRD-PARTY-NOTICES.txt",
  ]);
});

test("third-party notice extraction must match staged bytes", (t) => {
  const payloadPath = withStagingHashMismatchFixture(t, "THIRD-PARTY-NOTICES.txt");
  assertRejectedWith(runPackageVerifier(packagePath, msiPath, payloadPath), "negative-notices-hash.json", [
    "THIRD-PARTY-NOTICES.txt", "must match staged bytes",
  ]);
});

test("Given an authored SignTool payload, when package closure is verified, then source authoring is rejected", (t) => {
  const fixture = withFixture(t, (source) => injectAuthoredPayload(source, "signtool.exe"));
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-authoring-signtool-payload.json", [
    "Authoring package closure",
    "signtool.exe",
  ]);
});

for (const fixture of forbiddenStagedPayloads) {
  test(`Given a staged ${fixture.label}, when package closure is verified, then staging is rejected`, (t) => {
    const payloadPath = withStagingFixture(t, fixture.relativePath);
    const result = runPackageVerifier(packagePath, msiPath, payloadPath);
    assertRejectedWith(result, `negative-staging-${fixture.label.replaceAll(" ", "-")}.json`, [
      "Staged package closure",
      fixture.relativePath,
    ]);
  });
}

test("Given a third-party signer row in the compiled File table, when package closure is verified, then the MSI is rejected", (t) => {
  const fixture = withCompiledTableFixture(t, ({ tables }) => {
    assert.ok(Array.isArray(tables.File), "compiled snapshot must capture the File table");
    tables.File.push({
      fields: {
        File: "ForbiddenThirdPartySigner",
        Component_: "AppComponent",
        FileName: "third-party-signer.exe",
        FileSize: "7",
        Version: "",
        Language: "",
        Attributes: "512",
        Sequence: "3",
      },
    });
  });
  const result = runPackageVerifier(packagePath, fixture);
  assertRejectedWith(result, "negative-compiled-third-party-signer.json", [
    "MSI package closure",
    "third-party-signer.exe",
  ]);
});

test("Package closure keeps the SIP command compiled into Worker and constrains runtime launch paths", () => {
  const workerProject = readFileSync(join(root, "src/CodeSigner.Worker/CodeSigner.Worker.csproj"), "utf8");
  const sipCommand = readFileSync(
    join(root, "src/CodeSigner.Windows/Signing/WindowsPowerShellSipCommand.cs"),
    "utf8",
  );
  const sipBridge = readFileSync(
    join(root, "src/CodeSigner.Windows/Signing/WindowsPowerShellSipBridge.cs"),
    "utf8",
  );
  const sdkLocator = readFileSync(
    join(root, "src/CodeSigner.Windows/Readiness/TrustedSdkSignToolLocator.cs"),
    "utf8",
  );
  const sdkExecutor = readFileSync(
    join(root, "src/CodeSigner.Windows/Signing/TrustedSdkSignToolExecutor.cs"),
    "utf8",
  );
  const packageSource = readFileSync(packagePath, "utf8");

  assert.match(workerProject, /ProjectReference Include="\.\.\/CodeSigner\.Windows\/CodeSigner\.Windows\.csproj"/);
  assert.match(sipCommand, /internal const string SignAndVerify = """/);
  assert.match(sipBridge, /"System32"[\s\S]*?"WindowsPowerShell"[\s\S]*?"v1\.0"[\s\S]*?"powershell\.exe"/);
  assert.match(sipBridge, /startInfo\.ArgumentList\.Add\(WindowsPowerShellSipCommand\.SignAndVerify\)/);
  assert.match(sdkLocator, /"Windows Kits"[\s\S]*?"10"[\s\S]*?"bin"[\s\S]*?"x64"[\s\S]*?"signtool\.exe"/);
  assert.match(sdkExecutor, /CreateStartInfo\(currentCandidate\.Path, freshStage, leg\)/);
  assert.doesNotMatch(packageSource, /<File\b[^>]*Source="[^"]*(?:signtool\.exe|Windows Kits|powershell\.exe)/i);
});

test("Given the 1.0.8 baseline, when verified, then legacy routes and geometry remain accepted", () => {
  const result = runVerifier(packagePath);
  assert.ok(result.status === 0 || result.status === 1, result.stdout + result.stderr);
  const receipt = parseVerifierReceipt(result);
  assert.deepEqual(nonFontViolations(receipt), []);
  assert.notEqual(receipt.msi, null, "compiled MSI snapshot is mandatory");
  assert.notEqual(receipt.msiScenarios, null, "compiled MSI scenarios are mandatory");
  recordReceipt("wizard-contract-positive.json", receipt);
  assert.deepEqual(
    receipt.authoringScenarios.map(({ scenario, dialogRoute }) => [scenario, dialogRoute]),
    [
      ["FreshInstall", ["WelcomeDlg", "InstallDirectoryDlg", "InstallProgressDlg", "ExitDialog"]],
      ["MajorUpgrade", ["WelcomeDlg", "InstallDirectoryDlg", "InstallProgressDlg", "ExitDialog"]],
      ["Maintenance", ["InstallProgressDlg", "ExitDialog"]],
      ["Uninstall", ["UninstallProgressDlg", "ExitDialog"]],
      ["SilentQn", []],
    ],
  );
  assert.deepEqual(
    receipt.authoringScenarios.map((scenario) => scenario.selectedPairs.length),
    [1, 1, 1, 1, 0],
  );
});

test("Given a canonical source and compiled font contract, when verified, then it is accepted", (t) => {
  const fixture = withFontVerificationFixture(t);
  const result = runVerifier(fixture.sourcePath, fixture.compiledPath);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const receipt = parseVerifierReceipt(result);
  recordReceipt("font-contract-positive.json", receipt);
  assert.equal(receipt.success, true);
  assert.deepEqual(receipt.violations, []);
});

test("Given a missing font style row, when verified, then source and compiled contracts name it", (t) => {
  const fixture = withFontVerificationFixture(
    t,
    (source) => replaceExact(source, `${canonicalFontStyle}\n`, "", 1),
    ({ tables }) => {
      tables.TextStyle = [];
    },
  );
  const result = runVerifier(fixture.sourcePath, fixture.compiledPath);
  assertRejectedWithAll(result, "negative-font-style-missing.json", [
    ["Authoring font contract", fontStyleId, "observed 0"],
    ["MSI font contract", fontStyleId, "observed 0"],
  ]);
});

test("Given a missing DefaultUIFont property, when verified, then source and compiled contracts name it", (t) => {
  const fixture = withFontVerificationFixture(
    t,
    (source) => replaceExact(source, `${canonicalFontProperty}\n`, "", 1),
    ({ tables }) => {
      tables.Property = tables.Property.filter(({ fields }) =>
        fields.Property !== "DefaultUIFont"
      );
    },
  );
  const result = runVerifier(fixture.sourcePath, fixture.compiledPath);
  assertRejectedWithAll(result, "negative-default-ui-font-missing.json", [
    ["Authoring Property DefaultUIFont", "missing"],
    ["MSI Property DefaultUIFont", "missing"],
  ]);
});

test("Given a wrong-cased font face, when verified, then source and compiled contracts reject it", (t) => {
  const wrongCase = "Microsoft Yahei UI";
  const fixture = withFontVerificationFixture(
    t,
    (source) => replaceExact(
      source,
      `FaceName="${fontFaceName}"`,
      `FaceName="${wrongCase}"`,
      1,
    ),
    (tableFixture) => {
      const row = singleTableRow(
        tableFixture,
        "TextStyle",
        (fields) => fields.TextStyle === fontStyleId,
        fontStyleId,
      );
      row.FaceName = wrongCase;
    },
  );
  const result = runVerifier(fixture.sourcePath, fixture.compiledPath);
  assertRejectedWithAll(result, "negative-font-face-case.json", [
    ["Authoring TextStyle", fontStyleId, "exact-case", fontFaceName, wrongCase],
    ["MSI TextStyle", fontStyleId, "exact-case", fontFaceName, wrongCase],
  ]);
});

test("Given a wrong font size, when verified, then source and compiled contracts reject it", (t) => {
  const fixture = withFontVerificationFixture(
    t,
    (source) => replaceExact(source, 'Size="9"', 'Size="10"', 1),
    (tableFixture) => {
      const row = singleTableRow(
        tableFixture,
        "TextStyle",
        (fields) => fields.TextStyle === fontStyleId,
        fontStyleId,
      );
      row.Size = "10";
    },
  );
  const result = runVerifier(fixture.sourcePath, fixture.compiledPath);
  assertRejectedWithAll(result, "negative-font-size.json", [
    ["Authoring TextStyle", fontStyleId, "Size", "9", "10"],
    ["MSI TextStyle", fontStyleId, "Size", "9", "10"],
  ]);
});

test("Given wrong font style bits, when verified, then source and compiled contracts reject them", (t) => {
  const fixture = withFontVerificationFixture(
    t,
    (source) => replaceExact(source, canonicalFontStyle, canonicalFontStyle.replace(" />", ' Bold="yes" />'), 1),
    (tableFixture) => {
      const row = singleTableRow(
        tableFixture,
        "TextStyle",
        (fields) => fields.TextStyle === fontStyleId,
        fontStyleId,
      );
      row.StyleBits = "1";
    },
  );
  const result = runVerifier(fixture.sourcePath, fixture.compiledPath);
  assertRejectedWithAll(result, "negative-font-style-bits.json", [
    ["Authoring TextStyle", fontStyleId, "StyleBits", "0", "1"],
    ["MSI TextStyle", fontStyleId, "StyleBits", "0", "1"],
  ]);
});

test("Given a dangling DefaultUIFont reference, when verified, then source and compiled contracts reject it", (t) => {
  const danglingStyle = "Missing_Font_Style";
  const fixture = withFontVerificationFixture(
    t,
    (source) => replaceExact(
      source,
      `Value="${fontStyleId}"`,
      `Value="${danglingStyle}"`,
      1,
    ),
    (tableFixture) => {
      const row = singleTableRow(
        tableFixture,
        "Property",
        (fields) => fields.Property === "DefaultUIFont",
        "DefaultUIFont",
      );
      row.Value = danglingStyle;
    },
  );
  const result = runVerifier(fixture.sourcePath, fixture.compiledPath);
  assertRejectedWithAll(result, "negative-default-ui-font-dangling.json", [
    ["Authoring Property DefaultUIFont", "references missing TextStyle", danglingStyle],
    ["MSI Property DefaultUIFont", "references missing TextStyle", danglingStyle],
  ]);
});

test("Given duplicate font style rows, when verified, then source and compiled contracts reject them", (t) => {
  const fixture = withFontVerificationFixture(
    t,
    (source) => replaceExact(
      source,
      canonicalFontStyle,
      `${canonicalFontStyle}\n${canonicalFontStyle}`,
      1,
    ),
    ({ tables }) => {
      tables.TextStyle.push(structuredClone(tables.TextStyle[0]));
    },
  );
  const result = runVerifier(fixture.sourcePath, fixture.compiledPath);
  assertRejectedWithAll(result, "negative-font-style-duplicate.json", [
    ["Authoring font contract", fontStyleId, "observed 2"],
    ["MSI font contract", fontStyleId, "observed 2"],
  ]);
});

test("Given an absent compiled TextStyle table, when verified, then the reader returns a named violation", (t) => {
  const fixture = withFontVerificationFixture(t, undefined, ({ tables }) => {
    delete tables.TextStyle;
  });
  const result = runVerifier(fixture.sourcePath, fixture.compiledPath);
  assertRejectedWith(result, "negative-compiled-text-style-table-absent.json", [
    "MSI TextStyle table",
    "absent",
  ]);
});

test("Given legacy compiled metadata, when verified, then stale font metadata and obsolete recovery routes are rejected", (t) => {
  const sourcePath = withFixture(t, (source) => withCanonicalFontContract(source));
  const compiledPath = withCompiledTableFixture(t, ({ tables }) => {
    delete tables.TextStyle;
    tables.Property = tables.Property.filter(({ fields }) => fields.Property !== "DefaultUIFont");
    tables.Dialog = tables.Dialog.filter(({ fields }) => fields.Dialog !== "ExitDialog");
    tables.Control = tables.Control.filter(({ fields }) => fields.Dialog_ !== "ExitDialog");
    tables.ControlEvent = tables.ControlEvent.filter(({ fields }) => fields.Dialog_ !== "ExitDialog");
    tables.InstallUISequence = tables.InstallUISequence.filter(({ fields }) =>
      !["ExitDialog", "UserExit", "FatalError"].includes(fields.Action)
    );
  });
  const result = runVerifier(sourcePath, compiledPath);
  assertRejectedWithAll(result, "negative-preserved-108-font-contract.json", [
    ["MSI TextStyle table", "absent"],
    ["MSI Property DefaultUIFont", "missing"],
    ["MSI must route ExitDialog", "-1"],
    ["MSI must route UserExit", "-2"],
    ["MSI must route FatalError", "-3"],
  ]);
  const receipt = parseVerifierReceipt(result);
  const knownLegacyRecoveryViolations = [
    "MSI WelcomeDlg.NextHint text",
    "Expected exactly one MSI Dialog ExitDialog",
    "MSI ExitDialog.CloseButton",
    "MSI must route ExitDialog",
    "MSI must route UserExit",
    "MSI must route FatalError",
    "MSI scenario",
  ];
  assert.deepEqual(
    nonFontViolations(receipt).filter((violation) =>
      !knownLegacyRecoveryViolations.some((prefix) => violation.startsWith(prefix))
    ),
    [],
  );
  assert.deepEqual(
    receipt.msiScenarios.map(({ scenario, dialogRoute }) => [scenario, dialogRoute]),
    [
      ["FreshInstall", ["WelcomeDlg", "InstallDirectoryDlg", "InstallProgressDlg"]],
      ["MajorUpgrade", ["WelcomeDlg", "InstallDirectoryDlg", "InstallProgressDlg"]],
      ["Maintenance", ["InstallProgressDlg"]],
      ["Uninstall", ["UninstallProgressDlg"]],
      ["SilentQn", []],
    ],
  );
});

test("Given the former 623x450 DLU shells, when verified, then the reference families reject the old geometry", (t) => {
  const fixture = withFixture(t, (source) => setDialogShellGeometry(source, 623, 450));
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-former-shell-geometry.json", [
    "former 623x450 DLU shell",
    "reference family",
  ]);
});

test("Given a missing Welcome dialog route, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    mutateDialogId(source, "WelcomeDlg", "MissingWelcomeDlg"),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-missing-welcome-route.json", ["WelcomeDlg"]);
});

test("Given an incorrect Directory route, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    mutatePublishValue(
      source,
      "WelcomeDlg",
      "NextButton",
      "InstallDirectoryDlg",
      "InstallProgressDlg",
    ),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-directory-route.json", [
    "Authoring scenario FreshInstall route mismatch",
  ]);
});

test("Given a broken Welcome Next event, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    mutateFirstPublish(source, "WelcomeDlg", "NextButton"),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-next-event.json", ["WelcomeDlg.NextButton", "navigation mismatch"]);
});

test("Given a broken Directory Back event, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    mutateFirstPublish(source, "InstallDirectoryDlg", "BackButton"),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-back-event.json", ["InstallDirectoryDlg.BackButton", "navigation mismatch"]);
});

test("Given a broken wizard Cancel event, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    mutateFirstPublish(source, "WelcomeDlg", "CancelButton"),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-cancel-event.json", ["WelcomeDlg.CancelButton", "cancel navigation mismatch"]);
});

test("Given a broken Directory Install event, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    mutateFirstPublish(source, "InstallDirectoryDlg", "InstallButton"),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-install-event.json", [
    "InstallDirectoryDlg.InstallButton must publish SetTargetPath/[WIXUI_INSTALLDIR] exactly once",
  ]);
});

test("Given a broken Browse event, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    mutateFirstPublish(source, "InstallDirectoryDlg", "BrowseButton"),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-browse-event.json", [
    "InstallDirectoryDlg.BrowseButton browse navigation mismatch",
  ]);
});

test("Given a missing source SetProgress mapping, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    removeDialogSubscription(source, "InstallProgressDlg", "ProgressBar"),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-source-missing-setprogress.json", [
    "InstallProgressDlg.ProgressBar",
    "SetProgress/Progress",
  ]);
});

test("Given a lost INSTALLFOLDER binding, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    replaceExact(
      source,
      '<Property Id="WIXUI_INSTALLDIR" Value="INSTALLFOLDER" />',
      '<Property Id="WIXUI_INSTALLDIR" Value="TARGETDIR" />',
      1,
    ),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-installfolder-binding.json", [
    "Property WIXUI_INSTALLDIR must be 'INSTALLFOLDER'",
  ]);
});

test("Given an InstallPath bound away from WIXUI_INSTALLDIR, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    mutateControlAttribute(source, "InstallPath", "Property", "WIXUI_INSTALLDIR", "TARGETDIR"),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-installpath-binding.json", [
    "InstallDirectoryDlg.InstallPath property must be 'WIXUI_INSTALLDIR'",
  ]);
});

test("Given altered wizard geometry, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) => {
    const pattern = /(<Dialog\s+Id="WelcomeDlg"[^>]*\bWidth=")([0-9]+)(")/;
    const match = source.match(pattern);
    assert.ok(match, "WelcomeDlg width must be present for geometry mutation");
    return source.replace(pattern, `$1${Number(match[2]) + 1}$3`);
  });
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-wizard-geometry.json", ["WelcomeDlg", "geometry"]);
});

test("Given a missing side-panel bitmap control, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    removeDialogControl(source, "WelcomeDlg", "SidePanel"),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-side-panel-control.json", [
    "WelcomeDlg",
    "SidePanel",
  ]);
});

test("Given a one-DLU source anchor drift, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    driftDialogControlAttribute(source, "WelcomeDlg", "SidePanel", "Width", 1),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-source-one-dlu-anchor.json", [
    "WelcomeDlg.SidePanel",
    "reference family 'blue-side-panel'",
    "geometry mismatch",
  ]);
});

test("Given former compiled table geometry, when verified, then the compiled reference families reject it", (t) => {
  const fixture = withCompiledTableFixture(t, ({ tables }) => {
    const authoredDialogs = new Set([
      "WelcomeDlg",
      "InstallDirectoryDlg",
      "BrowseDlg",
      "InstallProgressDlg",
      "ExitDialog",
      "UninstallProgressDlg",
    ]);
    const rows = tables.Dialog.filter(({ fields }) => authoredDialogs.has(fields.Dialog));
    assert.equal(rows.length, 6, "compiled fixture must contain all six authored dialogs");
    for (const { fields } of rows) {
      fields.Width = "623";
      fields.Height = "450";
    }
  });
  const result = runVerifier(packagePath, fixture);
  assertRejectedWith(result, "negative-compiled-former-shell.json", [
    "MSI WelcomeDlg",
    "former 623x450 DLU shell",
    "reference family 'blue-side-panel'",
  ]);
});

test("Given a one-DLU compiled anchor drift, when verified, then the table fixture is rejected", (t) => {
  const fixture = withCompiledTableFixture(t, (tableFixture) => {
    const row = singleTableRow(
      tableFixture,
      "Control",
      (fields) => fields.Dialog_ === "WelcomeDlg" && fields.Control === "SidePanel",
      "WelcomeDlg.SidePanel",
    );
    row.Width = String(Number(row.Width) + 1);
  });
  const result = runVerifier(packagePath, fixture);
  assertRejectedWith(result, "negative-compiled-one-dlu-anchor.json", [
    "MSI WelcomeDlg.SidePanel",
    "reference family 'blue-side-panel'",
    "geometry mismatch",
  ]);
});

test("Given a broken compiled Browse route, when verified, then the table fixture is rejected", (t) => {
  const fixture = withCompiledTableFixture(t, (tableFixture) => {
    const row = singleTableRow(
      tableFixture,
      "ControlEvent",
      (fields) => fields.Dialog_ === "InstallDirectoryDlg" &&
        fields.Control_ === "BrowseButton" &&
        fields.Event === "SpawnDialog" &&
        fields.Argument === "BrowseDlg",
      "InstallDirectoryDlg.BrowseButton SpawnDialog",
    );
    row.Argument = "BrokenBrowseDlg";
  });
  const result = runVerifier(packagePath, fixture);
  assertRejectedWith(result, "negative-compiled-browse-route.json", [
    "MSI InstallDirectoryDlg.BrowseButton browse navigation mismatch",
  ]);
});

test("Given a missing compiled SetProgress mapping, when verified, then the table fixture is rejected", (t) => {
  const fixture = withCompiledTableFixture(t, ({ tables }) => {
    const before = tables.EventMapping.length;
    tables.EventMapping = tables.EventMapping.filter(({ fields }) =>
      !(fields.Dialog_ === "InstallProgressDlg" &&
        fields.Control_ === "ProgressBar" &&
        fields.Event === "SetProgress" &&
        fields.Attribute === "Progress"),
    );
    assert.equal(tables.EventMapping.length, before - 1, "one SetProgress row must be removed");
  });
  const result = runVerifier(packagePath, fixture);
  assertRejectedWith(result, "negative-compiled-missing-setprogress.json", [
    "MSI InstallProgressDlg.ProgressBar",
    "SetProgress/Progress EventMapping",
  ]);
});

test("Given a stale compiled table fixture hash, when read, then verification stops before contract output", (t) => {
  const fixture = withCompiledTableFixture(t, (tableFixture) => {
    tableFixture.sourceMsiSha256 = "0".repeat(64);
  });
  const result = runVerifier(packagePath, fixture);
  recordReceipt("negative-stale-compiled-table-fixture.json", {
    evidenceBinding: result.evidenceBinding,
    exitCode: result.status,
    stderr: result.stderr.trim(),
  });
  assert.equal(result.status, 2, result.stdout + result.stderr);
  assert.match(result.stderr, /source hash mismatch.*stale/i);
  assert.equal(result.stdout, "");
});

test("Given a malformed compiled table fixture schema, when read, then verification stops before contract output", (t) => {
  const fixture = withCompiledTableFixture(t, (tableFixture) => {
    tableFixture.schema = "broken-schema";
  });
  const result = runVerifier(packagePath, fixture);
  recordReceipt("negative-malformed-compiled-table-fixture.json", {
    evidenceBinding: result.evidenceBinding,
    exitCode: result.status,
    stderr: result.stderr.trim(),
  });
  assert.equal(result.status, 2, result.stdout + result.stderr);
  assert.match(result.stderr, /fixture schema must be/i);
  assert.equal(result.stdout, "");
});

test("Given an opaque Welcome title, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    mutateDialogControl(source, "WelcomeDlg", "Title", (control) =>
      replaceExact(control, 'Transparent="yes"', 'Transparent="no"', 1),
    ),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-welcome-title-transparency.json", [
    "WelcomeDlg.Title",
    "control attributes mismatch",
  ]);
});

test("Given missing Welcome guidance copy, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    removeDialogControl(source, "WelcomeDlg", "IntroText"),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-welcome-guidance-copy.json", [
    "WelcomeDlg",
    "control set mismatch",
  ]);
});

test("Given a missing side-panel Binary resource, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    replaceExact(
      source,
      '    <Binary Id="InstallerSidePanel" SourceFile="Assets/InstallerSidePanel.bmp" />\n',
      "",
      1,
    ),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-side-panel-binary.json", [
    "Authoring visual asset InstallerSidePanel",
    "observed 0",
  ]);
});

test("Given a wizard route that also runs in silent mode, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    injectExecuteSequenceDialogAction(source, "WelcomeDlg"),
  );
  const result = runVerifier(fixture);
  assertRejectedWith(result, "negative-silent-route.json", [
    "Authoring SilentQn route violation: custom dialog actions must not appear in InstallExecuteSequence.",
  ]);
});

test("Given current authoring, when verified, then all operation dialogs are exclusive", () => {
  const result = runVerifier(packagePath);
  assert.ok(result.status === 0 || result.status === 1, result.stdout + result.stderr);
  const receipt = parseVerifierReceipt(result);
  assert.deepEqual(nonFontViolations(receipt), []);
  recordReceipt("authoring-verification.json", receipt);
  assert.deepEqual(
    receipt.authoringScenarios.map((scenario) => [
      scenario.scenario,
      scenario.selectedPairs.length,
    ]),
    [
      ["FreshInstall", 1],
      ["MajorUpgrade", 1],
      ["Maintenance", 1],
      ["Uninstall", 1],
      ["SilentQn", 0],
    ],
  );
});

test("Given overlapping pair conditions, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    replaceExact(
      source,
      "Condition='REMOVE=&quot;ALL&quot; AND Installed'",
      "Condition='NOT (REMOVE=&quot;ALL&quot; AND Installed)'",
      1,
    ),
  );
  const result = runVerifier(fixture);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  const receipt = parseVerifierReceipt(result);
  recordReceipt("negative-overlap-rejection.json", receipt);
  assert.ok(
    receipt.violations.some((violation) =>
      violation.includes("scenario FreshInstall selected 2 dialog pairs"),
    ),
    result.stdout,
  );
});

test("Given installation wording in uninstall UI, when verified, then the fixture is rejected", (t) => {
  const fixture = withFixture(t, (source) =>
    replaceExact(
      source,
      "正在卸载 [ProductName]",
      "正在安装 [ProductName]",
      1,
    ),
  );
  const result = runVerifier(fixture);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  const receipt = parseVerifierReceipt(result);
  recordReceipt("negative-uninstall-wording-rejection.json", receipt);
  assert.ok(
    receipt.violations.some((violation) =>
      violation.includes("contains installation wording in uninstall UI"),
    ),
    result.stdout,
  );
});

test("Given the custom installer UI, when Windows Installer needs a recovery dialog, then all standard routes are present", () => {
  const source = readFileSync(packagePath, "utf8");
  assert.match(source, /<Property Id="ErrorDialog" Value="ErrorDlg"\s*\/>/, "ErrorDialog must bind to ErrorDlg");
  const errorDialog = dialogBlock(source, "ErrorDlg");
  assert.match(errorDialog.text, /^<Dialog[^>]*\bErrorDialog="yes"/, "ErrorDlg must be an MSI error dialog");
  assert.match(
    errorDialog.text,
    /^<Dialog[^>]*>\s*<Control Id="ErrorText"[^>]*\bTabSkip="no"/,
    "ErrorText must be the first non-skipped ErrorDlg control",
  );
  assert.match(
    errorDialog.text,
    /<Control Id="ErrorIcon" Type="Icon"[^>]*\bText="ErrorDialogIcon"/,
    "ErrorDlg must use the bundled error icon resource",
  );
  assert.match(source, /<Binary Id="ErrorDialogIcon" SourceFile="\.\.\/\.\.\/src\/CodeSigner\.App\/Assets\/CodeSigner\.ico"\s*\/>/, "ErrorDlg must bind its icon resource");
  for (const controlId of ["Y", "A", "C", "I", "N", "O", "R"]) {
    assert.match(
      errorDialog.text,
      new RegExp(`<Control Id="${controlId}"[^>]*\\bTabSkip="yes"`),
      `${controlId} must not displace ErrorText as the ErrorDlg first control`,
    );
  }
  for (const dialogId of ["FilesInUse", "FatalError", "UserExit", "ExitDialog"]) {
    assert.match(source, new RegExp(`<Dialog Id="${dialogId}"(?:\\s|>)`), `${dialogId} must be authored`);
  }
  for (const sequenceName of ["InstallUISequence", "AdminUISequence"]) {
    const sequence = source.match(new RegExp(`<${sequenceName}>[\\s\\S]*?</${sequenceName}>`));
    assert.notEqual(sequence, null, `${sequenceName} must be authored`);
    assert.match(sequence[0], /<Show Dialog="FatalError" OnExit="error"\s*\/>/, `${sequenceName} must route FatalError`);
    assert.match(sequence[0], /<Show Dialog="UserExit" OnExit="cancel"\s*\/>/, `${sequenceName} must route UserExit`);
    assert.match(sequence[0], /<Show Dialog="ExitDialog" OnExit="success"\s*\/>/, `${sequenceName} must route ExitDialog`);
  }
});
