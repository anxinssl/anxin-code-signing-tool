import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const inputs = [
  ["NSIS 3.12 installer components", "nsis-license.txt"],
  ["Lucide 0.468.0 (adapted WPF icons)", "lucide-license.txt"],
  [".NET runtime 10.0.10", "dotnet-runtime-license.txt"],
  [".NET runtime 10.0.10 third-party notices", "dotnet-runtime-third-party-notices.txt"],
  ["Windows Desktop runtime 10.0.10", "dotnet-windowsdesktop-license.txt"],
];
const content = "THIRD-PARTY NOTICES\n\nThese terms apply to the named third-party materials only.\n\n"
  + inputs.map(([name, file]) =>
    `${name}\n${"=".repeat(72)}\n\n${readFileSync(resolve(root, "licenses", file), "utf8").replace(/\r\n/g, "\n").trimEnd()}\n`)
    .join("\n");
const output = resolve(root, "THIRD-PARTY-NOTICES.txt");
if (process.argv.includes("--check")) {
  if (readFileSync(output, "utf8").replace(/\r\n/g, "\n") !== content) {
    throw new Error("THIRD-PARTY-NOTICES.txt must be regenerated from reviewed license texts.");
  }
} else {
  writeFileSync(output, content);
}
