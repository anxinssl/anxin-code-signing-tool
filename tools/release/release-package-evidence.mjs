const payloadNames = ["CodeSigner.App.exe", "CodeSigner.Worker.exe", "THIRD-PARTY-NOTICES.txt"];

function findPayload(files, fileName, surface, nameProperty) {
  if (!Array.isArray(files)) {
    throw new Error(`${surface} payload list is missing.`);
  }
  const matches = files.filter((file) => file?.[nameProperty] === fileName);
  if (matches.length !== 1) {
    throw new Error(`${surface} must contain exactly one ${fileName} payload.`);
  }
  const payload = matches[0];
  if (!Number.isSafeInteger(payload.size) || payload.size <= 0
      || typeof payload.sha256 !== "string" || !/^[0-9A-F]{64}$/.test(payload.sha256)) {
    throw new Error(`${surface} ${fileName} payload is malformed.`);
  }
  return payload;
}

export function readVerifiedPayloads(receipt) {
  if (receipt?.success !== true) {
    throw new Error("Package closure receipt did not pass.");
  }
  if (receipt.staging?.files?.length !== payloadNames.length
      || receipt.extractedMsiPayloads?.files?.length !== payloadNames.length) {
    throw new Error("Package closure must contain only the three required payloads.");
  }
  return payloadNames.map((fileName) => {
    const staged = findPayload(receipt.staging?.files, fileName, "Staging", "relativePath");
    const extracted = findPayload(receipt.extractedMsiPayloads?.files, fileName, "Extracted MSI", "fileName");
    if (staged.size !== extracted.size || staged.sha256 !== extracted.sha256) {
      throw new Error(`${fileName} staged and extracted MSI payloads diverge.`);
    }
    return {
      fileName,
      bytes: staged.size,
      sha256: staged.sha256.toLowerCase(),
    };
  });
}
