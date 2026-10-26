import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function normalizedText(bytes) {
  return bytes.toString("utf8").replace(/\r\n/g, "\n");
}

export function inspectFile(path, bytes, approvedBinaries = {}) {
  const errors = [];
  const normalized = path.replaceAll("\\", "/");
  if (/(^|\/)(?:\.env(?:\..*)?|\.local|\.omo|artifacts|logs?|node_modules|bin|obj)(?:\/|$)/i.test(normalized)
      && !normalized.endsWith("/.env.example") && normalized !== ".env.example") {
    errors.push("private-or-generated-path");
  }
  if (/\.(?:pfx|p12|pem|key|cer|crt|snk|log|jsonl|trx|binlog|user|suo)$/i.test(path)) {
    errors.push("sensitive-file-type");
  }
  const binaryExtension = /\.(?:exe|dll|msi|cab|ocx|png|ico|bmp|zip|rar|7z|pdf|docx|pdb)$/i.test(path);
  const isBinary = binaryExtension || bytes.includes(0);
  if (isBinary) {
    if (approvedBinaries[normalized] !== sha256(bytes)) errors.push("unreviewed-binary");
    return errors;
  }
  const text = bytes.toString("utf8");
  const patterns = [
    ["private-key", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/],
    ["github-token", /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/],
    ["aws-access-key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
    ["cloud-api-key", /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/],
    ["credential-in-url", /https?:\/\/[^/\s:@]+:[^/\s@]+@/i],
    ["jwt", /\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b/],
  ];
  for (const [name, pattern] of patterns) {
    if (pattern.test(text)) errors.push(name);
  }
  return errors;
}

export function checkPublicSource(root) {
  const files = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8", windowsHide: true })
    .split("\0").filter(Boolean);
  if (files.length === 0) throw new Error("No tracked files. Stage the reviewed public source first.");
  const manifest = JSON.parse(readFileSync(resolve(root, "release/metadata/public-source-baseline.json"), "utf8"));
  const textChanges = JSON.parse(readFileSync(resolve(root, "release/metadata/maintenance-text-changes.json"), "utf8"));
  const providerChanges = JSON.parse(readFileSync(resolve(root, "release/metadata/provider-neutral-changes.json"), "utf8"));
  const presentationChanges = JSON.parse(readFileSync(resolve(root, "release/metadata/presentation-changes.json"), "utf8"));
  const errors = [];
  for (const path of files) {
    for (const rule of inspectFile(path, readFileSync(resolve(root, path)), manifest.binaryAssets)) {
      errors.push(`${path}: ${rule}`);
    }
  }
  const actualFrozenPaths = files.filter((path) =>
    /^src\/.*\.(?:cs|xaml)$/.test(path) && path !== "src/CodeSigner.App/SettingsWindow.xaml.cs"
      && path !== "src/CodeSigner.App/Services/ProductionAdapters.cs"
      && !Object.hasOwn(manifest.approvedPresentationSource ?? {}, path)).sort();
  if (JSON.stringify(actualFrozenPaths) !== JSON.stringify(Object.keys(manifest.frozenSource).sort())) {
    errors.push("Frozen source inventory changed.");
  }
  for (const [path, expected] of Object.entries(manifest.frozenSource)) {
    let text = normalizedText(readFileSync(resolve(root, path)));
    const presentation = presentationChanges.files[path];
    if (presentation) {
      if (text.split(presentation.after).length !== 2) throw new Error(`Approved presentation change no longer matches: ${path}`);
      text = text.replace(presentation.after, presentation.before);
    }
    const approved = providerChanges.files[path];
    if (approved) {
      if (text.split(approved.after).length !== 2) throw new Error(`Approved change no longer matches: ${path}`);
      text = text.replace(approved.after, approved.before);
    }
    if (path === textChanges.file) {
      for (const [before, after] of textChanges.replacements) text = text.replaceAll(after, before);
    }
    if (sha256(text) !== expected) {
      errors.push(`${path}: frozen source changed`);
    }
  }
  for (const [path, expected] of Object.entries(manifest.approvedPresentationSource ?? {})) {
    if (!files.includes(path) || sha256(normalizedText(readFileSync(resolve(root, path)))) !== expected) {
      errors.push(`${path}: approved presentation or maintenance source changed`);
    }
  }
  const adapters = normalizedText(readFileSync(resolve(root, "src/CodeSigner.App/Services/ProductionAdapters.cs")))
    .replace("private readonly NsisMaintenance runner = new();", "private readonly WorkerRepairRunner runner = new();");
  const boundary = "\ninternal sealed class WindowsOperatorShell";
  if (!adapters.includes(boundary) || sha256(adapters.slice(0, adapters.indexOf(boundary))) !== manifest.signingAdaptersPrefixSha256) {
    errors.push("Signing adapters changed.");
  }
  for (const path of Object.keys(manifest.binaryAssets)) {
    if (!files.includes(path)) errors.push(`${path}: approved binary missing from index`);
  }
  if (errors.length) throw new Error(errors.join("\n"));
  return { version: manifest.version, files: files.length, frozenSourceFiles: actualFrozenPaths.length,
    approvedBinaries: Object.keys(manifest.binaryAssets).length, result: "passed" };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  console.log(JSON.stringify(checkPublicSource(resolve(import.meta.dirname, "..")), null, 2));
}
