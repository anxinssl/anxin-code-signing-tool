import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const EXIT_SCHEMA_OR_IDENTITY = 10;
const EXIT_STALE_FINGERPRINT = 11;
const EXIT_VERSION_HISTORY = 12;
const EXIT_IO = 13;
const HISTORY_PATH = "release/metadata/release-history.json";
const RELEASE_FAMILY_UPGRADE_CODE = "{C81BF087-67D0-41F3-8581-9E773813118B}";
const ROOT_INPUTS = [
  "Directory.Build.props",
  "Directory.Build.targets",
  "Directory.Packages.props",
  "global.json",
  "THIRD-PARTY-NOTICES.txt",
  "LICENSE",
  "NOTICE",
];
const INPUT_TREES = [
  ["src", new Set([".cs", ".csproj", ".xaml"])],
  ["packaging", new Set([".wxs", ".wixproj", ".ps1", ".nsi"])],
];
const PRODUCT_ASSET_TREES = [
  ["src/CodeSigner.App/Assets", new Set([".ico", ".png"])],
  ["packaging/msi/Assets", new Set([".bmp", ".ico", ".png"])],
];
const TEXT_INPUT_EXTENSIONS = new Set([
  ".cs",
  ".csproj",
  ".json",
  ".props",
  ".ps1",
  ".targets",
  ".wixproj",
  ".wxs",
  ".xaml",
  ".txt",
  ".nsi",
]);
const EXCLUDED_DIRECTORIES = new Set([
  ".build",
  ".omo",
  "bin",
  "docs",
  "evidence",
  "obj",
  "tests",
]);
const SEMVER_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const GUID_PATTERN = /^\{[0-9A-F]{8}-[0-9A-F]{4}-[1-5][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\}$/;
const FINGERPRINT_PATTERN = /^sha256:[0-9a-f]{64}$/;
const RELEASE_FIELDS = [
  "version",
  "assemblyVersion",
  "fileVersion",
  "informationalVersion",
  "productCode",
  "upgradeCode",
  "sourceFingerprint",
  "promoted",
];

class GuardError extends Error {
  constructor(exitCode, message, options) {
    super(message, options);
    this.name = "GuardError";
    this.exitCode = exitCode;
  }
}

function reject(exitCode, message, options) {
  throw new GuardError(exitCode, message, options);
}

function read(root, path, encoding) {
  try {
    return readFileSync(join(root, path), encoding);
  } catch (error) {
    reject(EXIT_IO, `Unable to read required release input: ${path}`, { cause: error });
  }
}

export function normalizeFingerprintPath(path) {
  return path.replaceAll("\\", "/").toLowerCase();
}

function normalizeFingerprintContent(path, contents) {
  if (!TEXT_INPUT_EXTENSIONS.has(extname(path).toLowerCase())) return contents;
  return Buffer.from(contents.toString("utf8").replaceAll("\r\n", "\n"), "utf8");
}

function walk(root, directory, extensions, inputs) {
  let entries;
  try {
    entries = readdirSync(join(root, directory), { withFileTypes: true });
  } catch (error) {
    reject(EXIT_IO, `Unable to enumerate release input directory: ${directory}`, { cause: error });
  }
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory() && !EXCLUDED_DIRECTORIES.has(entry.name.toLowerCase())) {
      walk(root, path, extensions, inputs);
    } else if (entry.isFile() && extensions.has(extname(entry.name).toLowerCase())) {
      inputs.push(path);
    }
  }
}

function walkProductAssets(root, directory, extensions, inputs) {
  const absoluteDirectory = join(root, directory);
  if (!existsSync(absoluteDirectory)) return;
  let entries;
  try {
    entries = readdirSync(absoluteDirectory, { withFileTypes: true });
  } catch (error) {
    reject(EXIT_IO, `Unable to enumerate release asset directory: ${directory}`, { cause: error });
  }
  for (const entry of entries) {
    if (entry.isFile() && extensions.has(extname(entry.name).toLowerCase())) {
      inputs.push(join(directory, entry.name));
    }
  }
}

function fingerprintInputs(root) {
  const inputs = [...ROOT_INPUTS];
  for (const [directory, extensions] of INPUT_TREES) walk(root, directory, extensions, inputs);
  for (const [directory, extensions] of PRODUCT_ASSET_TREES) {
    walkProductAssets(root, directory, extensions, inputs);
  }
  inputs.sort((left, right) => {
    const normalizedLeft = normalizeFingerprintPath(left);
    const normalizedRight = normalizeFingerprintPath(right);
    return normalizedLeft < normalizedRight ? -1 : normalizedLeft > normalizedRight ? 1 : 0;
  });
  const normalized = inputs.map(normalizeFingerprintPath);
  if (new Set(normalized).size !== normalized.length) {
    reject(EXIT_SCHEMA_OR_IDENTITY, "Fingerprint inputs collide after Windows path normalization.");
  }
  return inputs;
}

export function computeSourceFingerprint(rootPath) {
  const root = resolve(rootPath);
  const inputs = fingerprintInputs(root);
  const hash = createHash("sha256");
  hash.update("codesigner-release-source-v1\0");
  for (const path of inputs) {
    hash.update(normalizeFingerprintPath(path));
    hash.update("\0");
    hash.update(normalizeFingerprintContent(path, read(root, path)));
    hash.update("\0");
  }
  return { sourceFingerprint: `sha256:${hash.digest("hex")}`, inputCount: inputs.length };
}

function singleTag(text, name, source) {
  const matches = [...text.matchAll(new RegExp(`<${name}(?:\\s[^>]*)?>([^<]*)</${name}>`, "g"))];
  if (matches.length !== 1 || matches[0][1].trim() === "") {
    reject(EXIT_SCHEMA_OR_IDENTITY, `${source} must define exactly one non-empty ${name}.`);
  }
  return matches[0][1].trim();
}

function singleAttribute(text, name, source) {
  const matches = [...text.matchAll(new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`, "g"))];
  if (matches.length !== 1) {
    reject(EXIT_SCHEMA_OR_IDENTITY, `${source} must define exactly one ${name} attribute.`);
  }
  return matches[0][1];
}

function readCentralIdentity(root) {
  const source = "Directory.Build.props";
  const text = read(root, source, "utf8");
  const identity = {
    version: singleTag(text, "CodeSignerProductVersion", source),
    assemblyVersion: singleTag(text, "CodeSignerAssemblyVersion", source),
    fileVersion: singleTag(text, "CodeSignerFileVersion", source),
    informationalVersion: singleTag(text, "CodeSignerInformationalVersion", source),
    productCode: singleTag(text, "CodeSignerProductCode", source),
    upgradeCode: singleTag(text, "CodeSignerUpgradeCode", source),
  };
  if (!SEMVER_PATTERN.test(identity.version)
      || identity.assemblyVersion !== `${identity.version}.0`
      || identity.fileVersion !== `${identity.version}.0`
      || identity.informationalVersion !== identity.version
      || !GUID_PATTERN.test(identity.productCode)
      || !GUID_PATTERN.test(identity.upgradeCode)
      || identity.upgradeCode !== RELEASE_FAMILY_UPGRADE_CODE) {
    reject(EXIT_SCHEMA_OR_IDENTITY, "Central CodeSigner release identity is malformed or divergent.");
  }
  const bindings = {
    Version: "$(CodeSignerProductVersion)",
    AssemblyVersion: "$(CodeSignerAssemblyVersion)",
    FileVersion: "$(CodeSignerFileVersion)",
    InformationalVersion: "$(CodeSignerInformationalVersion)",
  };
  for (const [name, expected] of Object.entries(bindings)) {
    if (singleTag(text, name, source) !== expected) {
      reject(EXIT_SCHEMA_OR_IDENTITY, `${source} does not bind ${name} to the central identity.`);
    }
  }
  return identity;
}

function ensureProductProjectsDoNotDiverge(root, identity) {
  const projects = [
    "src/CodeSigner.App/CodeSigner.App.csproj",
    "src/CodeSigner.Worker/CodeSigner.Worker.csproj",
  ];
  const properties = {
    Version: [identity.version, "$(CodeSignerProductVersion)"],
    AssemblyVersion: [identity.assemblyVersion, "$(CodeSignerAssemblyVersion)"],
    FileVersion: [identity.fileVersion, "$(CodeSignerFileVersion)"],
    InformationalVersion: [identity.informationalVersion, "$(CodeSignerInformationalVersion)"],
  };
  for (const project of projects) {
    const text = read(root, project, "utf8");
    for (const [name, allowed] of Object.entries(properties)) {
      for (const match of text.matchAll(new RegExp(`<${name}(?:\\s[^>]*)?>([^<]*)</${name}>`, "g"))) {
        if (!allowed.includes(match[1].trim())) {
          reject(EXIT_SCHEMA_OR_IDENTITY, `${project} overrides ${name} with a divergent value.`);
        }
      }
    }
  }
}

function ensureInstallerConsumesCentralIdentity(root) {
  const project = "packaging/msi/CodeSigner.Installer.wixproj";
  const projectText = read(root, project, "utf8");
  const projectBindings = {
    InstallerProductVersion: "$(CodeSignerProductVersion)",
    InstallerProductCode: "$(CodeSignerProductCode)",
    InstallerUpgradeCode: "$(CodeSignerUpgradeCode)",
  };
  for (const [name, expected] of Object.entries(projectBindings)) {
    if (singleTag(projectText, name, project) !== expected) {
      reject(EXIT_SCHEMA_OR_IDENTITY, `${project} does not bind ${name} to the central identity.`);
    }
  }
  const constants = singleTag(projectText, "DefineConstants", project);
  for (const name of Object.keys(projectBindings)) {
    if (!constants.includes(`${name}=$(${name})`)) {
      reject(EXIT_SCHEMA_OR_IDENTITY, `${project} does not export ${name} to WiX.`);
    }
  }

  const packagePath = "packaging/msi/Package.wxs";
  const packageText = read(root, packagePath, "utf8");
  const attributes = {
    Version: "$(var.InstallerProductVersion)",
    ProductCode: "$(var.InstallerProductCode)",
    UpgradeCode: "$(var.InstallerUpgradeCode)",
  };
  for (const [name, expected] of Object.entries(attributes)) {
    if (singleAttribute(packageText, name, packagePath) !== expected) {
      reject(EXIT_SCHEMA_OR_IDENTITY, `${packagePath} has a divergent ${name}.`);
    }
  }
  if (packageText.includes("AllowSameVersionUpgrades")) {
    reject(EXIT_SCHEMA_OR_IDENTITY, "WiX same-version upgrades must remain disabled.");
  }
}

function parseHistory(root) {
  let history;
  try {
    history = JSON.parse(read(root, HISTORY_PATH, "utf8"));
  } catch (error) {
    if (error instanceof GuardError) throw error;
    reject(EXIT_SCHEMA_OR_IDENTITY, `${HISTORY_PATH} is not valid JSON.`, { cause: error });
  }
  if (history === null || typeof history !== "object" || Array.isArray(history)
      || history.schemaVersion !== 1 || history.product !== "CodeSigner"
      || !Array.isArray(history.releases) || history.releases.length < 2) {
    reject(EXIT_SCHEMA_OR_IDENTITY, `${HISTORY_PATH} has an invalid top-level schema.`);
  }
  return history;
}

function compareVersions(left, right) {
  const leftParts = left.split(".").map(Number);
  const rightParts = right.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index] - rightParts[index];
  }
  return 0;
}

function validateHistory(releases) {
  const productCodes = new Set();
  for (let index = 0; index < releases.length; index += 1) {
    const release = releases[index];
    if (release === null || typeof release !== "object" || Array.isArray(release)
        || Object.keys(release).sort().join("|") !== [...RELEASE_FIELDS].sort().join("|")) {
      reject(EXIT_SCHEMA_OR_IDENTITY, `Release history entry ${index} has an invalid schema.`);
    }
    if (!SEMVER_PATTERN.test(release.version)
        || release.assemblyVersion !== `${release.version}.0`
        || release.fileVersion !== `${release.version}.0`
        || release.informationalVersion !== release.version
        || !GUID_PATTERN.test(release.productCode)
        || !GUID_PATTERN.test(release.upgradeCode)
        || release.upgradeCode !== RELEASE_FAMILY_UPGRADE_CODE
        || typeof release.promoted !== "boolean") {
      reject(EXIT_SCHEMA_OR_IDENTITY, `Release history entry ${index} has a malformed identity.`);
    }
    const nullFingerprintAllowed = index === 0 && release.version === "1.0.0";
    if (!(nullFingerprintAllowed && release.sourceFingerprint === null)
        && (typeof release.sourceFingerprint !== "string"
          || !FINGERPRINT_PATTERN.test(release.sourceFingerprint))) {
      reject(EXIT_SCHEMA_OR_IDENTITY, `Release history entry ${index} has an invalid fingerprint.`);
    }
    if (index > 0 && compareVersions(releases[index - 1].version, release.version) >= 0) {
      reject(EXIT_VERSION_HISTORY, "Release versions must be unique and strictly increasing.");
    }
    const normalizedProductCode = release.productCode.toUpperCase();
    if (productCodes.has(normalizedProductCode)) {
      reject(EXIT_VERSION_HISTORY, "Every release must use a unique ProductCode.");
    }
    productCodes.add(normalizedProductCode);
    if (index > 0 && release.upgradeCode !== releases[0].upgradeCode) {
      reject(EXIT_SCHEMA_OR_IDENTITY, "UpgradeCode drifted from the existing product family.");
    }
  }
  if (releases.at(-1).sourceFingerprint === null) {
    reject(EXIT_SCHEMA_OR_IDENTITY, "The latest release must have a source fingerprint.");
  }
}

function loadReleaseState(rootPath) {
  const root = resolve(rootPath);
  const identity = readCentralIdentity(root);
  ensureProductProjectsDoNotDiverge(root, identity);
  ensureInstallerConsumesCentralIdentity(root);
  const history = parseHistory(root);
  const releases = history.releases;
  validateHistory(releases);
  const latest = releases.at(-1);
  for (const name of ["version", "assemblyVersion", "fileVersion", "informationalVersion", "productCode", "upgradeCode"]) {
    if (latest[name] !== identity[name]) {
      reject(EXIT_SCHEMA_OR_IDENTITY, `Current ${name} diverges from the latest release history entry.`);
    }
  }
  return { root, identity, history, latest };
}

export function checkRelease(rootPath) {
  const { root, identity, latest } = loadReleaseState(rootPath);
  const fingerprint = computeSourceFingerprint(root);
  if (latest.sourceFingerprint !== fingerprint.sourceFingerprint) {
    reject(EXIT_STALE_FINGERPRINT, "Product or installer source changed after the latest release entry was sealed.");
  }
  return { ok: true, ...identity, ...fingerprint };
}

function writeHistory(root, history) {
  const target = join(root, HISTORY_PATH);
  const temporary = `${target}.${process.pid}.${Date.now()}.tmp`;
  try {
    writeFileSync(temporary, `${JSON.stringify(history, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
    renameSync(temporary, target);
  } catch (error) {
    try {
      unlinkSync(temporary);
    } catch {
      // The temporary file may not have been created or may already have been renamed.
    }
    reject(EXIT_IO, `Unable to update current candidate history: ${HISTORY_PATH}`, { cause: error });
  }
}

export function updateCurrentCandidateFingerprint(rootPath) {
  const { root, identity, history, latest } = loadReleaseState(rootPath);
  if (latest.promoted) {
    reject(EXIT_VERSION_HISTORY, "A promoted release fingerprint is immutable; append a higher version.");
  }
  const fingerprint = computeSourceFingerprint(root);
  const updated = latest.sourceFingerprint !== fingerprint.sourceFingerprint;
  if (updated) {
    const releases = history.releases.map((release, index) =>
      index === history.releases.length - 1
        ? { ...release, sourceFingerprint: fingerprint.sourceFingerprint }
        : release);
    writeHistory(root, { ...history, releases });
  }
  return { ok: true, updated, version: identity.version, ...fingerprint };
}

function parseArguments(arguments_) {
  let mode;
  let root = process.cwd();
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--check"
        || argument === "--fingerprint"
        || argument === "--update-current-candidate-fingerprint") {
      if (mode !== undefined) reject(EXIT_SCHEMA_OR_IDENTITY, "Specify exactly one guard mode.");
      mode = argument;
    } else if (argument === "--root" && index + 1 < arguments_.length) {
      root = arguments_[index + 1];
      index += 1;
    } else {
      reject(EXIT_SCHEMA_OR_IDENTITY, `Unknown or incomplete argument: ${argument}`);
    }
  }
  if (mode === undefined) {
    reject(
      EXIT_SCHEMA_OR_IDENTITY,
      "Specify --check, --fingerprint, or --update-current-candidate-fingerprint.",
    );
  }
  return { mode, root };
}

function runCli() {
  try {
    const { mode, root } = parseArguments(process.argv.slice(2));
    const receipt = mode === "--check"
      ? checkRelease(root)
      : mode === "--fingerprint"
        ? computeSourceFingerprint(root)
        : updateCurrentCandidateFingerprint(root);
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  } catch (error) {
    const exitCode = error instanceof GuardError ? error.exitCode : EXIT_IO;
    const message = error instanceof Error ? error.message : "Unknown release guard failure.";
    process.stderr.write(`${JSON.stringify({ ok: false, exitCode, message })}\n`);
    process.exitCode = exitCode;
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) runCli();
