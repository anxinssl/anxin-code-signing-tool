import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { readVerifiedPayloads } from "./release-package-evidence.mjs";

const root = resolve(import.meta.dirname, "../..");
if (process.argv.length !== 2) {
  throw new Error("Usage: node tools/release/build-codesigner-signing-diagnostics-110.mjs");
}

function run(command, arguments_) {
  const result = spawnSync(command, arguments_, {
    cwd: root,
    encoding: "utf8",
    stdio: "pipe",
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${arguments_.join(" ")} failed with ${result.status}: ${result.stderr || result.stdout}`);
  }
  return result.stdout;
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function requireAbsent(path, label) {
  if (existsSync(path)) {
    throw new Error(`${label} already exists and is immutable: ${path}`);
  }
}

function sameRelease(left, right) {
  return left.version === right.version
    && left.productCode === right.productCode
    && left.upgradeCode === right.upgradeCode
    && left.sourceFingerprint === right.sourceFingerprint;
}

const release = JSON.parse(run("node", ["tools/release/verify-release-version.mjs", "--check"]));
const evidenceRoot = join(root, "artifacts", "release-evidence", release.version);
const outputRoot = join(root, "artifacts", "release", release.version);
requireAbsent(evidenceRoot, "Release evidence directory");
requireAbsent(outputRoot, "Release output directory");
mkdirSync(join(root, "artifacts", "release-evidence"), { recursive: true });
mkdirSync(join(root, "artifacts", "release"), { recursive: true });

const scratchRoot = join(root, "artifacts", "scratch");
mkdirSync(scratchRoot, { recursive: true });
const attemptRoot = mkdtempSync(join(scratchRoot, `release-${release.version}-`));
const draftEvidenceRoot = join(attemptRoot, "evidence");
const draftOutputRoot = join(attemptRoot, "output");

try {
  const staging = join(root, "artifacts", "staging");
  mkdirSync(staging, { recursive: true });
  run("dotnet", ["build", "packaging/msi/CodeSigner.Installer.wixproj", "-c", "Release", "-p:Platform=x64", "--no-restore"]);

  const app = join(staging, "CodeSigner.App.exe");
  const worker = join(staging, "CodeSigner.Worker.exe");
  if (!existsSync(app) || !existsSync(worker)) {
    throw new Error("WiX staging did not produce both CodeSigner executable files.");
  }

  const builtMsi = join(root, "packaging", "msi", "bin", "x64", "Release", "CodeSigner.Installer.msi");
  const finalMsi = join(outputRoot, `CodeSigner.Installer-${release.version}-win-x64.msi`);
  const draftMsi = join(draftOutputRoot, `CodeSigner.Installer-${release.version}-win-x64.msi`);
  if (!existsSync(builtMsi)) throw new Error("WiX build completed without producing the expected MSI.");
  mkdirSync(draftOutputRoot, { recursive: true });
  mkdirSync(draftEvidenceRoot, { recursive: true });
  copyFileSync(builtMsi, draftMsi);
  renameSync(draftOutputRoot, outputRoot);

  const featureEvidence = join(draftEvidenceRoot, "worker-feature-verification.json");
  run("pwsh", ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", "packaging/msi/Verify-WorkerFeatureMsi.ps1", "-MsiPath", finalMsi, "-EvidencePath", featureEvidence]);

  const packageEvidence = join(draftEvidenceRoot, "package-closure-verification.json");
  const wixToolsetDll = join(
    homedir(), ".nuget", "packages", "wixtoolset.sdk", "6.0.2", "tools", "net6.0", "wix.dll",
  );
  run("dotnet", [
    "run", "--project", "tools/installer-verifier/CodeSigner.InstallerVerifier.csproj", "-c", "Release", "--",
    "--source", "packaging/msi/Package.wxs",
    "--settings-source", "src/CodeSigner.App/SettingsWindow.xaml.cs",
    "--staging", staging,
    "--msi", finalMsi,
    "--wix-toolset-dll", wixToolsetDll,
    "--expected-version", release.version,
    "--expected-product-code", release.productCode,
    "--expected-upgrade-code", release.upgradeCode,
    "--receipt", packageEvidence,
  ]);

  const postBuildRelease = JSON.parse(run("node", ["tools/release/verify-release-version.mjs", "--check"]));
  if (!sameRelease(release, postBuildRelease)) {
    throw new Error("Release identity or source fingerprint changed during the package build.");
  }
  const [appPayload, workerPayload, noticesPayload] = readVerifiedPayloads(JSON.parse(readFileSync(packageEvidence, "utf8")));
  if (appPayload.sha256 !== sha256(app) || workerPayload.sha256 !== sha256(worker)
      || noticesPayload.sha256 !== sha256(join(staging, "THIRD-PARTY-NOTICES.txt"))) {
    throw new Error("Package closure payload hashes diverge from the current WiX staging files.");
  }

  const receipt = {
    schemaVersion: 2,
    status: "passed",
    release: postBuildRelease,
    app: appPayload,
    worker: workerPayload,
    notices: noticesPayload,
    msi: { path: finalMsi, bytes: readFileSync(finalMsi).byteLength, sha256: sha256(finalMsi) },
    workerFeatureEvidence: join(evidenceRoot, "worker-feature-verification.json"),
    packageClosureEvidence: join(evidenceRoot, "package-closure-verification.json"),
    installerExecution: "not-run",
    uac: "not-run",
    realSigning: "not-run",
    independentReview: "required-before-delivery",
  };
  writeFileSync(join(draftEvidenceRoot, "release-package.json"), `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  renameSync(draftEvidenceRoot, evidenceRoot);
  rmSync(attemptRoot, { recursive: true, force: true });
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
} catch (error) {
  if (!existsSync(evidenceRoot) && existsSync(outputRoot)) {
    rmSync(outputRoot, { recursive: true, force: true });
    process.stderr.write(`Unsealed delivery output discarded: ${outputRoot}\n`);
  }
  process.stderr.write(`Release attempt preserved for diagnosis: ${attemptRoot}\n`);
  throw error;
}
