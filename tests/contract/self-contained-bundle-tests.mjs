import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { inspectSelfContainedBundle } from "../../tools/release/verify-self-contained-bundle.mjs";

function fixture({ app = true, options, omit, typeOverride, staticSymbols } = {}) {
  const name = app ? "CodeSigner.App" : "CodeSigner.Worker";
  const frameworks = [{ name: "Microsoft.NETCore.App", version: "10.0.10" }];
  if (app) frameworks.push({ name: "Microsoft.WindowsDesktop.App", version: "10.0.10" });
  const config = Buffer.from(JSON.stringify({
    runtimeOptions: options ?? { tfm: "net10.0", includedFrameworks: frameworks },
  }));
  const files = [
    [`${name}.runtimeconfig.json`, 4, config],
    [`${name}.dll`, 1],
    ["System.Private.CoreLib.dll", 1],
    ["coreclr.dll", 2],
    ["clrjit.dll", 2],
  ];
  if (app) files.push(
    ["PresentationFramework.dll", 1],
    ["PresentationCore.dll", 1],
    ["WindowsBase.dll", 1],
    ["wpfgfx_cor3.dll", 2],
  );
  const int64 = (value) => {
    const bytes = Buffer.alloc(8);
    bytes.writeBigInt64LE(BigInt(value));
    return bytes;
  };
  const string = (value) => Buffer.concat([Buffer.from([Buffer.byteLength(value)]), Buffer.from(value)]);
  const prefix = Buffer.alloc(staticSymbols ? 2048 : 64);
  const pointer = staticSymbols ? 1024 : 0;
  if (staticSymbols) {
    prefix.writeUInt16LE(0x5a4d, 0);
    prefix.writeUInt32LE(128, 60);
    prefix.writeUInt32LE(0x4550, 128);
    prefix.writeUInt16LE(0x8664, 132);
    prefix.writeUInt16LE(1, 134);
    prefix.writeUInt16LE(240, 148);
    prefix.writeUInt16LE(0x20b, 152);
    prefix.writeUInt32LE(0x1000, 264);
    prefix.writeUInt32LE(0x1000, 404);
    prefix.writeUInt32LE(512, 408);
    prefix.writeUInt32LE(512, 412);
    prefix.writeUInt32LE(staticSymbols.length, 536);
    prefix.writeUInt32LE(0x1028, 544);
    let symbolOffset = 600;
    for (let index = 0; index < staticSymbols.length; index += 1) {
      prefix.writeUInt32LE(0x1000 + symbolOffset - 512, 552 + index * 4);
      prefix.write(staticSymbols[index], symbolOffset, "ascii");
      symbolOffset += staticSymbols[index].length + 1;
    }
  }
  Buffer.from("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae", "hex").copy(prefix, pointer + 8);
  const payloads = [];
  const entries = [];
  let offset = prefix.length;
  for (const [path, type, value = Buffer.from("fixture")] of files) {
    if (path === omit) continue;
    if (staticSymbols && ["coreclr.dll", "clrjit.dll"].includes(path)) continue;
    entries.push(Buffer.concat([
      int64(offset), int64(value.length), int64(0),
      Buffer.from([typeOverride?.[path] ?? type]), string(path),
    ]));
    payloads.push(value);
    offset += value.length;
  }
  prefix.writeBigInt64LE(BigInt(offset), pointer);
  const version = Buffer.alloc(12);
  version.writeUInt32LE(6);
  version.writeInt32LE(entries.length, 8);
  return Buffer.concat([
    prefix, ...payloads, version, string("fixture"),
    int64(0), int64(0), int64(prefix.length), int64(config.length), int64(0), ...entries,
  ]);
}

test("accepts statically linked .NET 10 Windows runtime exports without separate CLR DLLs", () => {
  const result = inspectSelfContainedBundle(fixture({
    staticSymbols: ["DotNetRuntimeInfo", "DotNetRuntimeContractDescriptor", "CLRJitAttachState"],
  }), "CodeSigner.App");
  assert.equal(result.nativeRuntime, "statically-linked");
});
test("rejects a native executable without the required static CLR exports", () => {
  assert.throws(() => inspectSelfContainedBundle(fixture({
    staticSymbols: ["UnrelatedExport"],
  }), "CodeSigner.App"), /coreclr/);
});
test("rejects static-runtime hosts that still request a global framework", () => {
  assert.throws(() => inspectSelfContainedBundle(fixture({
    staticSymbols: ["DotNetRuntimeInfo", "DotNetRuntimeContractDescriptor", "CLRJitAttachState"],
    options: { frameworks: [{ name: "Microsoft.NETCore.App", version: "10.0.0" }] },
  }), "CodeSigner.App"), /Framework-dependent/);
});
for (const app of [true, false]) {
  test(`accepts complete self-contained ${app ? "App" : "Worker"}`, () => {
    assert.equal(inspectSelfContainedBundle(fixture({ app }), app ? "CodeSigner.App" : "CodeSigner.Worker").selfContained, true);
  });
}
for (const key of ["framework", "frameworks"]) {
  test(`rejects external ${key} even when native runtime files are bundled`, () => {
    assert.throws(() => inspectSelfContainedBundle(fixture({
      options: { [key]: { name: "Microsoft.NETCore.App", version: "10.0.0" } },
    }), "CodeSigner.App"), /Framework-dependent/);
  });
}
test("rejects missing Windows desktop framework", () => {
  assert.throws(() => inspectSelfContainedBundle(fixture({
    options: { includedFrameworks: [{ name: "Microsoft.NETCore.App", version: "10.0.10" }] },
  }), "CodeSigner.App"), /Microsoft.WindowsDesktop.App/);
});
for (const omit of ["coreclr.dll", "clrjit.dll", "System.Private.CoreLib.dll", "PresentationFramework.dll", "wpfgfx_cor3.dll"]) {
  test(`rejects missing ${omit}`, () => {
    assert.throws(() => inspectSelfContainedBundle(fixture({ omit }), "CodeSigner.App"), /Missing bundled runtime file/);
  });
}
test("rejects native runtime with an incorrect bundle type", () => {
  assert.throws(() => inspectSelfContainedBundle(fixture({ typeOverride: { "coreclr.dll": 1 } }), "CodeSigner.App"), /coreclr/);
});
test("rejects missing marker", () => {
  assert.throws(() => inspectSelfContainedBundle(Buffer.alloc(128), "CodeSigner.App"), /marker/);
});
test("rejects truncated manifest", () => {
  const bytes = fixture();
  assert.throws(() => inspectSelfContainedBundle(bytes.subarray(0, bytes.length - 4), "CodeSigner.App"), /Truncated/);
});
test("rejects header outside file bounds", () => {
  const bytes = fixture();
  bytes.writeBigInt64LE(BigInt(bytes.length + 1));
  assert.throws(() => inspectSelfContainedBundle(bytes, "CodeSigner.App"), /header/);
});
test("installer isolates publish artifacts and checks embedded bytes before staging", () => {
  const xml = readFileSync(resolve(import.meta.dirname, "../../packaging/msi/CodeSigner.Installer.wixproj"), "utf8");
  assert.equal((xml.match(/--artifacts-path/g) ?? []).length, 2);
  assert.equal((xml.match(/--self-contained true/g) ?? []).length, 2);
  assert.ok(xml.indexOf("verify-self-contained-bundle.mjs") < xml.indexOf("<Copy SourceFiles="));
  assert.ok(!xml.includes('Targets="Publish"'));
});
