import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { inflateRawSync } from "node:zlib";

// .NET single-file bundle v6: apphost marker, header, then typed file entries.
const SIGNATURE = Buffer.from(
  "8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae",
  "hex",
);

function hasStaticWindowsRuntime(bytes) {
  if (bytes.length < 64 || bytes.readUInt16LE(0) !== 0x5a4d) return false;
  const pe = bytes.readUInt32LE(60);
  if (pe + 264 > bytes.length || bytes.readUInt32LE(pe) !== 0x4550 ||
      bytes.readUInt16LE(pe + 4) !== 0x8664 || bytes.readUInt16LE(pe + 24) !== 0x20b) return false;
  const sectionCount = bytes.readUInt16LE(pe + 6);
  const sectionTable = pe + 24 + bytes.readUInt16LE(pe + 20);
  if (sectionTable + sectionCount * 40 > bytes.length) return false;
  function map(rva, size) {
    for (let index = 0; index < sectionCount; index += 1) {
      const section = sectionTable + index * 40;
      const start = bytes.readUInt32LE(section + 12);
      const rawSize = bytes.readUInt32LE(section + 16);
      const raw = bytes.readUInt32LE(section + 20);
      if (rva >= start && rva + size <= start + rawSize &&
          raw + rva - start + size <= bytes.length) return raw + rva - start;
    }
    throw new Error("Invalid PE export address.");
  }
  const exportRva = bytes.readUInt32LE(pe + 24 + 112);
  if (!exportRva) return false;
  const exports = map(exportRva, 40);
  const count = bytes.readUInt32LE(exports + 24);
  if (count > 10000) throw new Error("Invalid PE export count.");
  const names = map(bytes.readUInt32LE(exports + 32), count * 4);
  const symbols = new Set();
  for (let index = 0; index < count; index += 1) {
    const offset = map(bytes.readUInt32LE(names + index * 4), 1);
    const end = bytes.indexOf(0, offset);
    if (end < offset || end - offset > 1024) throw new Error("Invalid PE export name.");
    symbols.add(bytes.subarray(offset, end).toString("ascii"));
  }
  return ["DotNetRuntimeInfo", "DotNetRuntimeContractDescriptor", "CLRJitAttachState"]
    .every((name) => symbols.has(name));
}

export function inspectSelfContainedBundle(bytes, applicationName) {
  if (!["CodeSigner.App", "CodeSigner.Worker"].includes(applicationName)) {
    throw new Error("Unknown product executable.");
  }
  const marker = bytes.indexOf(SIGNATURE);
  if (marker < 8 || bytes.indexOf(SIGNATURE, marker + 1) !== -1) {
    throw new Error("Expected one .NET bundle marker.");
  }
  let cursor = marker - 8;
  function take(size) {
    if (!Number.isSafeInteger(size) || size < 0 || cursor + size > bytes.length) {
      throw new Error("Truncated bundle.");
    }
    const start = cursor;
    cursor += size;
    return bytes.subarray(start, cursor);
  }
  function int64() {
    const value = Number(take(8).readBigInt64LE());
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("Invalid bundle offset or size.");
    return value;
  }
  function string() {
    let length = 0;
    for (let index = 0; index < 5; index += 1) {
      const value = take(1)[0];
      length += (value & 127) * 2 ** (index * 7);
      if ((value & 128) === 0) return take(length).toString("utf8");
    }
    throw new Error("Invalid bundle string length.");
  }
  const header = int64();
  if (header <= marker + SIGNATURE.length || header >= bytes.length) {
    throw new Error("Invalid bundle header location.");
  }
  cursor = header;
  const major = take(4).readUInt32LE();
  const minor = take(4).readUInt32LE();
  if (major !== 6 || minor !== 0) throw new Error("Unsupported bundle format; update the release verifier.");
  const count = take(4).readInt32LE();
  if (count < 1 || count > 10000) throw new Error("Invalid bundle file count.");
  const bundleId = string();
  int64(); // deps.json offset
  int64(); // deps.json size
  const configOffset = int64();
  const configSize = int64();
  int64(); // bundle flags
  const entries = new Map();
  for (let index = 0; index < count; index += 1) {
    const offset = int64();
    const size = int64();
    const compressedSize = int64();
    const type = take(1)[0];
    const name = string();
    if (entries.has(name) || offset + (compressedSize || size) > header || size === 0) {
      throw new Error("Invalid or duplicate bundle entry.");
    }
    entries.set(name, { offset, size, compressedSize, type });
  }
  const config = entries.get(`${applicationName}.runtimeconfig.json`);
  if (!config || config.type !== 4 || config.offset !== configOffset || config.size !== configSize) {
    throw new Error("Runtime configuration is missing or inconsistent with the bundle header.");
  }
  const stored = bytes.subarray(config.offset, config.offset + (config.compressedSize || config.size));
  const decoded = config.compressedSize
    ? inflateRawSync(stored, { maxOutputLength: 1024 * 1024 })
    : stored;
  if (decoded.length !== config.size) throw new Error("Invalid runtime configuration size.");
  const options = JSON.parse(decoded.toString("utf8")).runtimeOptions;
  if (!options || options.framework !== undefined || options.frameworks !== undefined) {
    throw new Error("Framework-dependent runtime configuration: this executable requires an installed .NET runtime.");
  }
  const frameworks = options.includedFrameworks;
  const requiredFrameworks = applicationName === "CodeSigner.App"
    ? ["Microsoft.NETCore.App", "Microsoft.WindowsDesktop.App"]
    : ["Microsoft.NETCore.App"];
  for (const name of requiredFrameworks) {
    if (!Array.isArray(frameworks) ||
        !frameworks.some((item) => item.name === name && /^10\.0\.\d+$/.test(item.version))) {
      throw new Error(`Missing bundled framework: ${name}`);
    }
  }
  const requiredFiles = [
    [`${applicationName}.dll`, 1],
    ["System.Private.CoreLib.dll", 1],
  ];
  const staticRuntime = hasStaticWindowsRuntime(bytes);
  if (!staticRuntime) requiredFiles.push(["coreclr.dll", 2], ["clrjit.dll", 2]);
  if (applicationName === "CodeSigner.App") {
    requiredFiles.push(
      ["PresentationFramework.dll", 1],
      ["PresentationCore.dll", 1],
      ["WindowsBase.dll", 1],
      ["wpfgfx_cor3.dll", 2],
    );
  }
  for (const [name, type] of requiredFiles) {
    if (entries.get(name)?.type !== type) throw new Error(`Missing bundled runtime file: ${name}`);
  }
  return {
    applicationName,
    bundleId,
    fileCount: count,
    includedFrameworks: frameworks,
    nativeRuntime: staticRuntime ? "statically-linked" : "bundled-libraries",
    sha256: createHash("sha256").update(bytes).digest("hex").toUpperCase(),
    selfContained: true,
  };
}

function main(args) {
  const results = [];
  const seen = new Set();
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    if (!["--app", "--worker"].includes(option) || !args[index + 1] || seen.has(option)) {
      throw new Error("Use --app <exe> and/or --worker <exe>, once each.");
    }
    seen.add(option);
    const path = resolve(args[index + 1]);
    results.push({
      path,
      ...inspectSelfContainedBundle(readFileSync(path), option === "--app" ? "CodeSigner.App" : "CodeSigner.Worker"),
    });
  }
  if (results.length === 0) throw new Error("At least one product executable is required.");
  return { ok: true, executables: results };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    console.log(JSON.stringify(main(process.argv.slice(2)), null, 2));
  } catch (error) {
    console.error(JSON.stringify({ ok: false, error: error.message }));
    process.exitCode = 1;
  }
}
