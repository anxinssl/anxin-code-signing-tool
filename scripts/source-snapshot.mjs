import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";

const root = resolve(import.meta.dirname, "..");
const version = readFileSync(join(root, "Directory.Build.props"), "utf8")
  .match(/<CodeSignerProductVersion>([^<]+)</)[1];
const files = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean).sort();
if (!files.length) throw new Error("Stage the reviewed source first.");
if (execFileSync("git", ["diff", "--name-only"], { cwd: root, encoding: "utf8" }).trim())
  throw new Error("Unstaged changes would not be included in the source archive.");
const tree = execFileSync("git", ["write-tree"], { cwd: root, encoding: "utf8" }).trim();
const dir = join(root, "artifacts", "source", version);
mkdirSync(dir, { recursive: true });
const archive = join(dir, `Anxin-Code-Signing-Certificate-Tool-${version}-source.zip`);
execFileSync("git", ["archive", "--format=zip", `--prefix=Anxin-CodeSigner-${version}/`, `--output=${archive}`, tree], { cwd: root });
const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");
const manifest = {
  version, sourceTree: tree, sourceArchive: archive.split(/[\\/]/).at(-1),
  sourceArchiveSha256: sha256(readFileSync(archive)),
  files: Object.fromEntries(files.map(path => [path, sha256(execFileSync("git", ["show", `:${path}`], { cwd: root, maxBuffer: 16 * 1024 * 1024 }))])),
};
const payload = join(root, "artifacts", "nsis-payload", version);
mkdirSync(payload, { recursive: true });
writeFileSync(join(payload, "source-manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(JSON.stringify({ version, sourceTree: tree, sourceArchive: archive, sourceArchiveSha256: manifest.sourceArchiveSha256 }, null, 2));
