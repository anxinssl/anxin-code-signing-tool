import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const REPOSITORY_ROOT = resolve(import.meta.dirname, "../..");
const GUARD_PATH = join(REPOSITORY_ROOT, "tools", "release", "verify-release-version.mjs");
const HISTORY_PATH = join(REPOSITORY_ROOT, "release", "metadata", "release-history.json");
const VERSION = "1.0.26";
const PRODUCT_CODE = "{93187D49-5FD0-429A-A890-558230DC03AA}";
const CURRENT_VERSION = "1.0.44";
const CURRENT_PRODUCT_CODE = "{E59DA367-7017-4A82-B1EC-C2E751FAAA48}";
const UPGRADE_CODE = "{C81BF087-67D0-41F3-8581-9E773813118B}";
const OLD_PRODUCT_CODE = "{4B8C46E0-10E2-4F04-A741-53C8D21BC4A0}";
const ROOT_INPUTS = [
  "Directory.Build.props",
  "Directory.Build.targets",
  "Directory.Packages.props",
  "global.json",
  "THIRD-PARTY-NOTICES.txt",
  "LICENSE",
  "NOTICE",
];
const PRODUCT_ASSET_ROOTS = [
  ["src/CodeSigner.App/Assets", [".ico", ".png"]],
  ["packaging/msi/Assets", [".bmp", ".ico", ".png"]],
];

function write(root, path, contents) {
  const destination = join(root, path);
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, contents);
}

function normalizeFingerprintPath(path) {
  return path.replaceAll("\\", "/").toLowerCase();
}

function collectFingerprintInputs(root) {
  const inputs = [...ROOT_INPUTS];
  const walk = (directory, extensions) => {
    for (const entry of readdirSync(join(root, directory), { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "bin" && entry.name !== "obj") walk(path, extensions);
      } else if (extensions.some((extension) => entry.name.toLowerCase().endsWith(extension))) {
        inputs.push(path);
      }
    }
  };
  walk("src", [".cs", ".csproj", ".xaml"]);
  walk("packaging", [".wxs", ".wixproj", ".ps1"]);
  for (const [directory, extensions] of PRODUCT_ASSET_ROOTS) {
    const absoluteDirectory = join(root, directory);
    try {
      for (const entry of readdirSync(absoluteDirectory, { withFileTypes: true })) {
        if (entry.isFile() && extensions.some((extension) => entry.name.toLowerCase().endsWith(extension))) {
          inputs.push(join(directory, entry.name));
        }
      }
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  return inputs.sort((left, right) =>
    normalizeFingerprintPath(left).localeCompare(normalizeFingerprintPath(right), "en"),
  );
}

function fingerprint(root) {
  const hash = createHash("sha256");
  hash.update("codesigner-release-source-v1\0");
  for (const path of collectFingerprintInputs(root)) {
    hash.update(normalizeFingerprintPath(path));
    hash.update("\0");
    hash.update(readFileSync(join(root, path)));
    hash.update("\0");
  }
  return `sha256:${hash.digest("hex")}`;
}

function centralProps() {
  return `<Project>
  <PropertyGroup>
    <CodeSignerProductVersion>${VERSION}</CodeSignerProductVersion>
    <CodeSignerAssemblyVersion>${VERSION}.0</CodeSignerAssemblyVersion>
    <CodeSignerFileVersion>${VERSION}.0</CodeSignerFileVersion>
    <CodeSignerInformationalVersion>${VERSION}</CodeSignerInformationalVersion>
    <CodeSignerProductCode>${PRODUCT_CODE}</CodeSignerProductCode>
    <CodeSignerUpgradeCode>${UPGRADE_CODE}</CodeSignerUpgradeCode>
  </PropertyGroup>
  <PropertyGroup Condition="'$(MSBuildProjectExtension)' == '.csproj'">
    <Version>$(CodeSignerProductVersion)</Version>
    <AssemblyVersion>$(CodeSignerAssemblyVersion)</AssemblyVersion>
    <FileVersion>$(CodeSignerFileVersion)</FileVersion>
    <InformationalVersion>$(CodeSignerInformationalVersion)</InformationalVersion>
  </PropertyGroup>
</Project>
`;
}

function releaseHistory(sourceFingerprint) {
  return {
    schemaVersion: 1,
    product: "CodeSigner",
    releases: [
      {
        version: "1.0.0",
        assemblyVersion: "1.0.0.0",
        fileVersion: "1.0.0.0",
        informationalVersion: "1.0.0",
        productCode: OLD_PRODUCT_CODE,
        upgradeCode: UPGRADE_CODE,
        sourceFingerprint: null,
        promoted: true,
      },
      {
        version: VERSION,
        assemblyVersion: `${VERSION}.0`,
        fileVersion: `${VERSION}.0`,
        informationalVersion: VERSION,
        productCode: PRODUCT_CODE,
        upgradeCode: UPGRADE_CODE,
        sourceFingerprint,
        promoted: false,
      },
    ],
  };
}

function createFixture(t) {
  const root = mkdtempSync(join(tmpdir(), "codesigner-release-guard-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  write(root, "Directory.Build.props", centralProps());
  write(root, "Directory.Build.targets", "<Project />\n");
  write(root, "Directory.Packages.props", "<Project />\n");
  write(root, "global.json", '{"sdk":{"version":"10.0.302"}}\n');
  write(root, "THIRD-PARTY-NOTICES.txt", "Synthetic third-party notice fixture.\n");
  write(root, "LICENSE", "Synthetic license fixture.\n");
  write(root, "NOTICE", "Synthetic copyright fixture.\n");
  write(root, "src/CodeSigner.App/App.cs", "namespace CodeSigner.App;\n");
  write(root, "src/CodeSigner.App/CodeSigner.App.csproj", '<Project Sdk="Microsoft.NET.Sdk" />\n');
  write(root, "src/CodeSigner.Worker/Program.cs", "namespace CodeSigner.Worker;\n");
  write(root, "src/CodeSigner.Worker/CodeSigner.Worker.csproj", '<Project Sdk="Microsoft.NET.Sdk" />\n');
  write(
    root,
    "packaging/msi/CodeSigner.Installer.wixproj",
    `<Project Sdk="WixToolset.Sdk/6.0.2"><PropertyGroup>
<InstallerProductVersion>$(CodeSignerProductVersion)</InstallerProductVersion>
<InstallerProductCode>$(CodeSignerProductCode)</InstallerProductCode>
<InstallerUpgradeCode>$(CodeSignerUpgradeCode)</InstallerUpgradeCode>
<DefineConstants>$(DefineConstants);InstallerProductVersion=$(InstallerProductVersion);InstallerProductCode=$(InstallerProductCode);InstallerUpgradeCode=$(InstallerUpgradeCode)</DefineConstants>
</PropertyGroup></Project>\n`,
  );
  write(
    root,
    "packaging/msi/Package.wxs",
    '<Wix><Package Version="$(var.InstallerProductVersion)" ProductCode="$(var.InstallerProductCode)" UpgradeCode="$(var.InstallerUpgradeCode)"><MajorUpgrade /></Package></Wix>\n',
  );
  write(root, "packaging/msi/Verify.ps1", "Write-Output ok\n");
  const history = releaseHistory(fingerprint(root));
  write(root, "release/metadata/release-history.json", `${JSON.stringify(history, null, 2)}\n`);
  return { root, history };
}

function runGuard(root, mode = "--check") {
  return spawnSync(process.execPath, [GUARD_PATH, mode, "--root", root], {
    encoding: "utf8",
    timeout: 10_000,
    windowsHide: true,
  });
}

test("live release identity is centralized and the guard accepts the tree", () => {
  const result = runGuard(REPOSITORY_ROOT);
  const expectedExit = Number.parseInt(process.env.CODESIGNER_EXPECT_LIVE_GUARD_EXIT ?? "0", 10);
  assert.ok(expectedExit === 0 || expectedExit === 11);
  assert.equal(result.status, expectedExit, result.stderr || result.stdout);
  if (expectedExit === 11) {
    assert.equal(JSON.parse(result.stderr).exitCode, 11);
    return;
  }
  const receipt = JSON.parse(result.stdout);
  assert.deepEqual(
    [receipt.version, receipt.assemblyVersion, receipt.fileVersion, receipt.informationalVersion],
    [CURRENT_VERSION, `${CURRENT_VERSION}.0`, `${CURRENT_VERSION}.0`, CURRENT_VERSION],
  );
  assert.equal(receipt.productCode, CURRENT_PRODUCT_CODE);
  assert.equal(receipt.upgradeCode, UPGRADE_CODE);
});

test("release history preserves archived identities and seals the current candidate", () => {
  const history = JSON.parse(readFileSync(HISTORY_PATH, "utf8"));
  assert.equal(history.releases[0].version, "1.0.0");
  assert.equal(history.releases[0].sourceFingerprint, `sha256:${"0".repeat(64)}`);
  assert.equal(history.releases[0].promoted, true);
  assert.equal(history.releases[1].version, "1.0.1");
  assert.equal(history.releases[1].promoted, true);
  assert.equal(history.releases[2].version, "1.0.2");
  assert.equal(history.releases[2].promoted, true);
  assert.equal(history.releases[3].version, "1.0.3");
  assert.equal(history.releases[3].promoted, true);
  assert.equal(history.releases[4].version, "1.0.4");
  assert.equal(history.releases[4].promoted, true);
  assert.equal(history.releases[5].version, "1.0.5");
  assert.equal(history.releases[5].promoted, true);
  assert.equal(history.releases[6].version, "1.0.6");
  assert.equal(history.releases[6].promoted, true);
  assert.equal(history.releases[7].version, "1.0.7");
  assert.equal(history.releases[7].promoted, true);
  assert.equal(history.releases[8].version, "1.0.8");
  assert.equal(history.releases[8].promoted, true);
  assert.equal(history.releases[9].version, "1.0.9");
  assert.equal(history.releases[9].promoted, true);
  assert.equal(history.releases[10].version, "1.0.10");
  assert.equal(history.releases[10].promoted, true);
  assert.equal(history.releases[11].version, "1.0.11");
  assert.equal(history.releases[11].promoted, true);
  assert.equal(history.releases[12].version, "1.0.12");
  assert.equal(history.releases[12].promoted, true);
  assert.equal(history.releases.find(entry => entry.version === "1.0.15").promoted, true);
  for (let patch = 17; patch <= 36; patch++) {
    const entry = history.releases.find(release => release.version === `1.0.${patch}`);
    assert.ok(entry, `Missing historical version 1.0.${patch}`);
    assert.equal(entry.promoted, patch === 30);
  }
  assert.equal(history.releases.at(-1).version, CURRENT_VERSION);
  assert.match(history.releases.at(-1).sourceFingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(history.releases.at(-1).sourceFingerprint, history.releases.at(-2).sourceFingerprint);
  assert.equal(history.releases.at(-1).promoted, false);
});

test("WiX consumes the central identity and disables same-version upgrades", () => {
  const props = readFileSync(join(REPOSITORY_ROOT, "Directory.Build.props"), "utf8");
  const wixProject = readFileSync(
    join(REPOSITORY_ROOT, "packaging/msi/CodeSigner.Installer.wixproj"),
    "utf8",
  );
  const packageSource = readFileSync(
    join(REPOSITORY_ROOT, "packaging/msi/Package.wxs"),
    "utf8",
  );
  assert.ok(props.includes(`<CodeSignerProductVersion>${CURRENT_VERSION}</CodeSignerProductVersion>`));
  assert.match(wixProject, /<InstallerProductVersion>\$\(CodeSignerProductVersion\)<\/InstallerProductVersion>/);
  assert.match(packageSource, /UpgradeCode="\$\(var\.InstallerUpgradeCode\)"/);
  assert.doesNotMatch(packageSource, /AllowSameVersionUpgrades/);
});

test("WiX installer builds stage freshly published App and Worker payloads before packaging", () => {
  const wixProject = readFileSync(
    join(REPOSITORY_ROOT, "packaging/msi/CodeSigner.Installer.wixproj"),
    "utf8",
  );
  assert.match(
    wixProject,
    /<Target Name="StageCodeSignerInstallerPayload" BeforeTargets="CoreCompile">/,
  );
  assert.match(
    wixProject,
    /<Exec Command="[^"\r\n]* publish [^"\r\n]*src\\CodeSigner\.App\\CodeSigner\.App\.csproj[^"\r\n]*--self-contained true[^"\r\n]*--artifacts-path/,
  );
  assert.match(
    wixProject,
    /<Exec Command="[^"\r\n]* publish [^"\r\n]*src\\CodeSigner\.Worker\\CodeSigner\.Worker\.csproj[^"\r\n]*--self-contained true[^"\r\n]*--artifacts-path/,
  );
  assert.match(
    wixProject,
    /DestinationFiles="\$\(CodeSignerInstallerStagingDirectory\)CodeSigner\.App\.exe"/,
  );
  assert.match(
    wixProject,
    /DestinationFiles="\$\(CodeSignerInstallerStagingDirectory\)CodeSigner\.Worker\.exe"/,
  );
});

test("MSBuild gates only Release product publish and baseline installer compilation", () => {
  const targets = readFileSync(join(REPOSITORY_ROOT, "Directory.Build.targets"), "utf8");
  assert.match(
    targets,
    /BeforeTargets="PrepareForPublish"[\s\S]*?'\$\(Configuration\)' == 'Release'[\s\S]*?CodeSigner\.App[\s\S]*?CodeSigner\.Worker/,
  );
  assert.match(
    targets,
    /BeforeTargets="CoreCompile"[\s\S]*?'\$\(Configuration\)' == 'Release'[\s\S]*?'\$\(MSBuildProjectExtension\)' == '\.wixproj'[\s\S]*?'\$\(LifecycleTestVariant\)' == 'Baseline'/,
  );
  assert.equal(targets.match(/node tools\/release\/verify-release-version\.mjs --check/g)?.length, 2);
});

test("valid fixture passes without modifying its dirty working files", (t) => {
  const { root } = createFixture(t);
  write(root, "untracked-dirty.txt", "preserve me\n");
  const before = readFileSync(join(root, "untracked-dirty.txt"), "utf8");
  const result = runGuard(root);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(join(root, "untracked-dirty.txt"), "utf8"), before);
});

test("candidate fingerprint update preserves promoted history and is idempotent", (t) => {
  const { root } = createFixture(t);
  const historyPath = join(root, "release/metadata/release-history.json");
  const promotedBefore = JSON.parse(readFileSync(historyPath, "utf8")).releases[0];
  write(root, "src/CodeSigner.App/App.cs", "namespace CodeSigner.App; // final candidate\n");

  const update = runGuard(root, "--update-current-candidate-fingerprint");

  assert.equal(update.status, 0, update.stderr);
  const receipt = JSON.parse(update.stdout);
  assert.equal(receipt.updated, true);
  const historyAfter = JSON.parse(readFileSync(historyPath, "utf8"));
  assert.deepEqual(historyAfter.releases[0], promotedBefore);
  assert.equal(historyAfter.releases.at(-1).sourceFingerprint, receipt.sourceFingerprint);
  assert.equal(runGuard(root).status, 0);
  const bytesAfterUpdate = readFileSync(historyPath, "utf8");
  const repeatedUpdate = runGuard(root, "--update-current-candidate-fingerprint");
  assert.equal(repeatedUpdate.status, 0, repeatedUpdate.stderr);
  assert.equal(JSON.parse(repeatedUpdate.stdout).updated, false);
  assert.equal(readFileSync(historyPath, "utf8"), bytesAfterUpdate);
});

test("candidate fingerprint update refuses to modify a promoted release", (t) => {
  const { root, history } = createFixture(t);
  history.releases.at(-1).promoted = true;
  write(root, "release/metadata/release-history.json", `${JSON.stringify(history, null, 2)}\n`);
  write(root, "src/CodeSigner.App/App.cs", "namespace CodeSigner.App; // post-release change\n");
  const historyPath = join(root, "release/metadata/release-history.json");
  const before = readFileSync(historyPath, "utf8");

  const result = runGuard(root, "--update-current-candidate-fingerprint");

  assert.equal(result.status, 12);
  assert.equal(readFileSync(historyPath, "utf8"), before);
});

test("higher candidate may supersede an unpromoted candidate without falsifying promotion", (t) => {
  const { root, history } = createFixture(t);
  const nextVersion = VERSION.replace(/\d+$/, (patch) => `${Number(patch) + 1}`);
  const nextProductCode = "{9AFC5599-4A7F-43E9-9C9B-832B2B7569A8}";
  write(
    root,
    "Directory.Build.props",
    centralProps().replaceAll(VERSION, nextVersion).replace(PRODUCT_CODE, nextProductCode),
  );
  history.releases.push({
    ...history.releases.at(-1),
    version: nextVersion,
    assemblyVersion: `${nextVersion}.0`,
    fileVersion: `${nextVersion}.0`,
    informationalVersion: nextVersion,
    productCode: nextProductCode,
    sourceFingerprint: fingerprint(root),
    promoted: false,
  });
  write(root, "release/metadata/release-history.json", `${JSON.stringify(history, null, 2)}\n`);
  const historyBeforeGuard = readFileSync(join(root, "release/metadata/release-history.json"), "utf8");

  const result = runGuard(root);

  assert.equal(result.status, 0, result.stderr || result.stdout);
  const persistedHistory = readFileSync(join(root, "release/metadata/release-history.json"), "utf8");
  assert.equal(persistedHistory, historyBeforeGuard);
  assert.equal(JSON.parse(persistedHistory).releases.at(-2).promoted, false);
});

test("malformed release JSON exits 10", (t) => {
  const { root } = createFixture(t);
  write(root, "release/metadata/release-history.json", "{\n");
  assert.equal(runGuard(root).status, 10);
});

test("artifact identity divergence and UpgradeCode drift exit 10", async (t) => {
  const first = createFixture(t);
  write(first.root, "Directory.Build.props", centralProps().replace(VERSION, "1.0.3"));
  assert.equal(runGuard(first.root).status, 10);

  const second = createFixture(t);
  second.history.releases.at(-1).upgradeCode = "{AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA}";
  write(second.root, "release/metadata/release-history.json", `${JSON.stringify(second.history)}\n`);
  assert.equal(runGuard(second.root).status, 10);
});

test("App, Worker, and MSI identity overrides exit 10", (t) => {
  const app = createFixture(t);
  write(
    app.root,
    "src/CodeSigner.App/CodeSigner.App.csproj",
    '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><Version>9.0.0</Version></PropertyGroup></Project>\n',
  );
  assert.equal(runGuard(app.root).status, 10);

  const worker = createFixture(t);
  write(
    worker.root,
    "src/CodeSigner.Worker/CodeSigner.Worker.csproj",
    '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><FileVersion>9.0.0.0</FileVersion></PropertyGroup></Project>\n',
  );
  assert.equal(runGuard(worker.root).status, 10);

  const msi = createFixture(t);
  const packagePath = "packaging/msi/Package.wxs";
  const packageSource = readFileSync(join(msi.root, packagePath), "utf8");
  write(msi.root, packagePath, packageSource.replace("$(var.InstallerProductCode)", OLD_PRODUCT_CODE));
  assert.equal(runGuard(msi.root).status, 10);
});

test("latest release null fingerprint exits 10", (t) => {
  const { root, history } = createFixture(t);
  history.releases.at(-1).sourceFingerprint = null;
  write(root, "release/metadata/release-history.json", `${JSON.stringify(history)}\n`);
  assert.equal(runGuard(root).status, 10);
});

test("one-byte product source mutation exits 11", (t) => {
  const { root } = createFixture(t);
  write(root, "src/CodeSigner.App/App.cs", "namespace CodeSigner.App; // changed\n");
  assert.equal(runGuard(root).status, 11);
});

test("shipped third-party notice mutation exits 11", (t) => {
  const { root } = createFixture(t);
  write(root, "THIRD-PARTY-NOTICES.txt", "Changed notice.\n");
  const result = runGuard(root);
  assert.equal(result.status, 11, result.stderr || result.stdout);
});

function assertAssetMutationExit11(t, relativePath, bytes) {
  const { root, history } = createFixture(t);
  write(root, relativePath, Buffer.from(bytes));
  history.releases.at(-1).sourceFingerprint = fingerprint(root);
  write(root, "release/metadata/release-history.json", `${JSON.stringify(history, null, 2)}\n`);

  const assetPath = join(root, relativePath);
  const asset = readFileSync(assetPath);
  asset[asset.length - 1] ^= 0xff;
  writeFileSync(assetPath, asset);

  const result = runGuard(root);
  assert.equal(result.status, 11, result.stderr || result.stdout);
  assert.equal(JSON.parse(result.stderr).exitCode, 11);
}

test("one-byte shipped .ico asset mutation exits 11", (t) => {
  assertAssetMutationExit11(t, "src/CodeSigner.App/Assets/CodeSigner.ico", [0, 1, 2, 3]);
});

test("one-byte shipped .png asset mutation exits 11", (t) => {
  assertAssetMutationExit11(t, "src/CodeSigner.App/Assets/CodeSigner.png", [4, 5, 6, 7]);
});

test("one-byte shipped installer .bmp asset mutation exits 11", (t) => {
  assertAssetMutationExit11(t, "packaging/msi/Assets/InstallerSidePanel.bmp", [8, 9, 10, 11]);
});

test("nested temporary, generated, and evidence asset paths are excluded", (t) => {
  const { root, history } = createFixture(t);
  const excludedPaths = [
    "src/CodeSigner.App/.tmp/test.ico",
    "src/CodeSigner.App/Assets/.tmp/test.ico",
    "src/CodeSigner.App/.build/generated/test.png",
    "packaging/msi/evidence/test.ico",
  ];
  for (const relativePath of excludedPaths) write(root, relativePath, Buffer.from([8, 9, 10, 11]));
  history.releases.at(-1).sourceFingerprint = fingerprint(root);
  write(root, "release/metadata/release-history.json", `${JSON.stringify(history, null, 2)}\n`);

  for (const relativePath of excludedPaths) {
    const assetPath = join(root, relativePath);
    const asset = readFileSync(assetPath);
    asset[asset.length - 1] ^= 0xff;
    writeFileSync(assetPath, asset);
    const result = runGuard(root);
    assert.equal(result.status, 0, result.stderr || result.stdout);
  }
});

test("non-increasing versions and duplicate ProductCodes exit 12", (t) => {
  const first = createFixture(t);
  first.history.releases.at(-1).promoted = true;
  first.history.releases.push({
    ...first.history.releases.at(-1),
    productCode: "{BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB}",
    promoted: false,
  });
  write(first.root, "release/metadata/release-history.json", `${JSON.stringify(first.history)}\n`);
  assert.equal(runGuard(first.root).status, 12);

  const second = createFixture(t);
  second.history.releases.at(-1).promoted = true;
  second.history.releases.push({
    ...second.history.releases.at(-1),
    version: "1.0.2",
    assemblyVersion: "1.0.2.0",
    fileVersion: "1.0.2.0",
    informationalVersion: "1.0.2",
    promoted: false,
  });
  write(second.root, "release/metadata/release-history.json", `${JSON.stringify(second.history)}\n`);
  assert.equal(runGuard(second.root).status, 12);
});

test("missing repository input exits 13", () => {
  assert.equal(runGuard(join(tmpdir(), "codesigner-release-guard-does-not-exist")).status, 13);
});

test("generated, test, documentation, evidence, and history bytes are outside the fingerprint", (t) => {
  const { root, history } = createFixture(t);
  for (const path of [
    "tests/a.cs",
    "docs/a.md",
    ".omo/evidence/a.cs",
    ".build/a.cs",
    "src/CodeSigner.App/bin/a.cs",
    "src/docs/a.cs",
    "src/tests/a.xaml",
    "packaging/.build/a.wxs",
    "packaging/evidence/a.ps1",
    "packaging/msi/obj/a.wxs",
  ]) write(root, path, "ignored mutation\n");
  write(root, "release/metadata/release-history.json", JSON.stringify(history));
  assert.equal(runGuard(root).status, 0);
});

test("fingerprint path normalization handles Windows separators and case", async () => {
  const module = await import(pathToFileURL(GUARD_PATH));
  assert.equal(
    module.normalizeFingerprintPath("SRC\\CodeSigner.App\\Program.CS"),
    "src/codesigner.app/program.cs",
  );
});

test("source fingerprint is stable across LF and CRLF checkout representations", (t) => {
  const { root } = createFixture(t);
  const sourcePath = "src/CodeSigner.App/App.cs";
  const lfSource = readFileSync(join(root, sourcePath), "utf8");
  assert.equal(lfSource.includes("\r"), false);

  write(root, sourcePath, lfSource.replaceAll("\n", "\r\n"));

  const result = runGuard(root);
  assert.equal(result.status, 0, result.stderr || result.stdout);
});
