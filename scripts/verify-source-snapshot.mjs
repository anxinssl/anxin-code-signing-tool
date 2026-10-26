import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve, join } from "node:path";
const root = resolve(import.meta.dirname, "..");
const version = readFileSync(join(root, "Directory.Build.props"), "utf8").match(/<CodeSignerProductVersion>([^<]+)</)[1];
const manifest = JSON.parse(readFileSync(join(root, "artifacts/nsis-payload", version, "source-manifest.json"), "utf8"));
const tree = execFileSync("git", ["write-tree"], { cwd: root, encoding: "utf8" }).trim();
if (execFileSync("git", ["diff", "--name-only"], { cwd: root, encoding: "utf8" }).trim() || manifest.sourceTree !== tree)
  throw new Error("Source differs from the snapshot. Stage reviewed files and regenerate the source snapshot.");
if (manifest.version !== version || !/^[a-zA-Z0-9.-]+\.zip$/.test(manifest.sourceArchive))
  throw new Error("Malformed source identity.");
const archive = join(root, "artifacts/source", version, manifest.sourceArchive);
const hash = createHash("sha256").update(readFileSync(archive)).digest("hex");
if (hash !== manifest.sourceArchiveSha256) throw new Error("Corresponding-source archive hash mismatch.");
for (const [path, expected] of Object.entries(manifest.files)) {
  const actual = createHash("sha256").update(readFileSync(join(root, path))).digest("hex");
  if (actual !== expected) throw new Error(`Working source bytes differ from source archive: ${path}`);
}
console.log(JSON.stringify({ version, sourceTree: tree, sourceArchiveSha256: hash, verified: true }));
