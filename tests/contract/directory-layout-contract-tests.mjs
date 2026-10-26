import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative, resolve } from "node:path";
import test from "node:test";

const REPOSITORY_ROOT = resolve(import.meta.dirname, "../..");
const CONTRACT_PATH = "tests/contract/directory-layout-contract-tests.mjs";
const EXCLUDED_DIRECTORIES = new Set([
  ".build",
  ".codegraph",
  ".git",
  ".omo",
  ".pytest_cache",
  ".ruff_cache",
  ".venv",
  "artifacts",
  "bin",
  "obj",
]);
const TEXT_EXTENSIONS = new Set([
  ".config",
  ".csproj",
  ".json",
  ".md",
  ".mjs",
  ".props",
  ".ps1",
  ".py",
  ".sln",
  ".targets",
  ".txt",
  ".wixproj",
  ".wxs",
]);
const REQUIRED_FILES = [
  "packaging/msi/CodeSigner.Installer.wixproj",
  "packaging/msi/Package.wxs",
  "packaging/msi/Assets/InstallerPanelFill.bmp",
  "packaging/msi/Assets/InstallerSidePanel.bmp",
  "src/CodeSigner.App/Assets/CodeSigner.ico",
  "tools/compatibility-probe/CodeSigner.CompatibilityProbe.csproj",
  "tools/installer-verifier/CodeSigner.InstallerVerifier.csproj",
  "tools/release/verify-release-version.mjs",
  "tools/release/build-codesigner-signing-diagnostics-110.mjs",
  "scripts/check-public-source.mjs",
  "scripts/test-public-source.ps1",
  "tests/fixtures/ui-baseline/baseline.json",
  "tools/asset-pipeline/__init__.py",
  "tools/asset-pipeline/product-icon-core.py",
  "tools/asset-pipeline/product-icon-pipeline.py",
  "tools/asset-pipeline/product-icon-validation.py",
  "tools/asset-pipeline/test-product-icon-pipeline.py",
  "tests/contract/release-version-guard-tests.mjs",
  "tests/contract/installer-ui-contract-tests.mjs",
  "release/metadata/release-history.json",
];
const LEGACY_PATH_SEGMENTS = [
  ["installer", "CodeSigner.Installer"],
  ["tools", "CodeSigner.CompatibilityProbe"],
  ["tools", "CodeSigner.InstallerVerifier"],
  ["tools", "verify-release-version.mjs"],
  ["tools", "build-codesigner-signing-diagnostics-110.mjs"],
  ["tools", "verify-signing-diagnostics-baseline.mjs"],
  ["tools", "product_icon_core.py"],
  ["tools", "product_icon_pipeline.py"],
  ["tools", "product_icon_validation.py"],
  ["tools", "test_product_icon_pipeline.py"],
  ["tests", "ReleaseVersionGuardTests.mjs"],
  ["tests", "InstallerUiContractTests.mjs"],
  ["release", "CodeSigner.ReleaseHistory.json"],
  [".build", "staging"],
];
const FORBIDDEN_BROKER_PATHS = [
  "src/CodeSigner.PublicationBroker",
  "src/CodeSigner.Core/publication-broker",
  "src/CodeSigner.Windows/Files/PublicationBrokerSecureFileCommitter.cs",
];
const FORBIDDEN_BROKER_LITERALS = [
  "CodeSigner.PublicationBroker",
  "CodeSignerPublicationBroker",
  "PublicationBrokerSecureFileCommitter",
  "protectedResultPath",
  "receiptSha256",
  "callerSid",
  "jobId",
];
const BROKER_SCAN_ROOTS = ["src", "tests", "packaging", "tools", "scripts", "docs", "release"];
const BROKER_SCAN_FILES = ["CodeSigner.sln", "README.md"];

function trackedPaths(root) {
  const result = spawnSync("git", ["ls-files", "-z"], {
    cwd: root,
    encoding: "utf8",
    timeout: 10_000,
    windowsHide: true,
  });
  if (result.status === 0) return result.stdout.split("\0").filter(Boolean);

  const paths = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && EXCLUDED_DIRECTORIES.has(entry.name)) continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else paths.push(relative(root, path).replaceAll("\\", "/"));
    }
  };
  walk(root);
  return paths;
}

function textPaths(root) {
  return trackedPaths(root).filter((path) =>
    path === ".gitignore" || TEXT_EXTENSIONS.has(extname(path).toLowerCase()),
  );
}

function brokerScanTextPaths(root) {
  const paths = [];
  const walk = (directory) => {
    if (!existsSync(directory)) return;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && EXCLUDED_DIRECTORIES.has(entry.name)) continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else {
        const relativePath = relative(root, path).replaceAll("\\", "/");
        if (TEXT_EXTENSIONS.has(extname(relativePath).toLowerCase())) paths.push(relativePath);
      }
    }
  };
  for (const directory of BROKER_SCAN_ROOTS) walk(join(root, directory));
  for (const path of BROKER_SCAN_FILES) {
    if (existsSync(join(root, path))) paths.push(path);
  }
  return paths;
}

function copyTrackedTree(sourceRoot, targetRoot) {
  for (const path of trackedPaths(sourceRoot)) {
    const source = join(sourceRoot, path);
    if (!existsSync(source) || !statSync(source).isFile()) continue;
    const target = join(targetRoot, path);
    mkdirSync(dirname(target), { recursive: true });
    cpSync(source, target);
  }
}

function validateLayout(root) {
  const errors = [];
  for (const path of REQUIRED_FILES) {
    if (!existsSync(join(root, path))) errors.push(`required path is missing: ${path}`);
  }

  for (const path of FORBIDDEN_BROKER_PATHS) {
    if (existsSync(join(root, path))) errors.push(`publication broker path remains: ${path}`);
  }

  const solution = readFileSync(join(root, "CodeSigner.sln"), "utf8");
  const solutionPattern = /^Project\("[^"]+"\) = "[^"]+", "([^"]+\.(?:csproj|wixproj))",/gmu;
  for (const match of solution.matchAll(solutionPattern)) {
    const path = match[1].replaceAll("\\", "/");
    if (!existsSync(join(root, path))) errors.push(`solution project does not resolve: ${path}`);
  }

  const referencePattern = /<ProjectReference\s+Include="([^"]+)"/gu;
  for (const path of textPaths(root).filter((candidate) => /\.(?:csproj|wixproj)$/u.test(candidate))) {
    const source = readFileSync(join(root, path), "utf8");
    for (const match of source.matchAll(referencePattern)) {
      const target = resolve(root, dirname(path), match[1]);
      if (!existsSync(target)) {
        errors.push(`project reference does not resolve: ${path} -> ${match[1]}`);
      }
    }
  }

  for (const path of textPaths(root)) {
    if (path === CONTRACT_PATH) continue;
    const source = readFileSync(join(root, path), "utf8");
    const normalizedSource = source.replace(/\\+/gu, "/");
    for (const segments of LEGACY_PATH_SEGMENTS) {
      const legacyPath = segments.join("/");
      if (normalizedSource.includes(legacyPath)) {
        errors.push(`legacy path literal remains in ${path}: ${legacyPath}`);
      }
    }
  }


  for (const path of brokerScanTextPaths(root)) {
    if (path === CONTRACT_PATH) continue;
    const source = readFileSync(join(root, path), "utf8");
    for (const literal of FORBIDDEN_BROKER_LITERALS) {
      if (source.includes(literal)) {
        errors.push(`publication broker literal remains in ${path}: ${literal}`);
      }
    }
  }
  return errors;
}

test("copied tree rejects broken references, legacy paths, and publication Broker surfaces", (t) => {
  const fixture = mkdtempSync(join(tmpdir(), "codesigner-layout-negative-"));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  copyTrackedTree(REPOSITORY_ROOT, fixture);

  const projectPath = join(fixture, "tests/CodeSigner.IntegrationTests/CodeSigner.IntegrationTests.csproj");
  const source = readFileSync(projectPath, "utf8");
  const projectReferencePattern = /\.\.\/\.\.\/tools\/[^"]+\/CodeSigner\.CompatibilityProbe\.csproj/u;
  assert.equal(source.match(projectReferencePattern)?.length, 1, "expected one compatibility probe reference");
  const legacyDirectory = ["installer", "CodeSigner.Installer"].join("/");
  const escapedLegacyDirectory = ["tools", "CodeSigner.CompatibilityProbe"].join("\\\\");
  const modified = `${source.replace(projectReferencePattern, "../../tools/missing-probe/CodeSigner.CompatibilityProbe.csproj")}\n<!-- ${legacyDirectory} ${escapedLegacyDirectory} -->\n`;
  writeFileSync(projectPath, modified, "utf8");
  const brokerProject = join(fixture, "src/CodeSigner.PublicationBroker/CodeSigner.PublicationBroker.csproj");
  mkdirSync(dirname(brokerProject), { recursive: true });
  writeFileSync(brokerProject, `${FORBIDDEN_BROKER_LITERALS.join("\n")}\n`, "utf8");

  const errors = validateLayout(fixture);
  const expectedLegacyProbePath = ["tools", "CodeSigner.CompatibilityProbe"].join("/");
  assert.ok(errors.some((error) => error.includes("project reference does not resolve")), errors.join("\n"));
  assert.ok(errors.some((error) => error.includes("legacy path literal remains")), errors.join("\n"));
  assert.ok(errors.some((error) => error.includes(expectedLegacyProbePath)), errors.join("\n"));
  assert.ok(errors.some((error) => error.includes("publication broker path remains")), errors.join("\n"));
  for (const literal of FORBIDDEN_BROKER_LITERALS) {
    assert.ok(errors.some((error) => error.endsWith(`: ${literal}`)), errors.join("\n"));
  }
});

test("actual tree satisfies the packaging, tool, release, and project reference layout", () => {
  assert.deepEqual(validateLayout(REPOSITORY_ROOT), []);
});
