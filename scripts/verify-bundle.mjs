import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

function sortJsonValue(value) {
  if (Array.isArray(value)) return value.map(sortJsonValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortJsonValue(value[key])]),
    );
  }
  return value;
}

function stableStringify(value) {
  return JSON.stringify(sortJsonValue(value));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function main() {
  const [, , bundlePath, originalPath, encryptedOriginalPath] = process.argv;
  if (!bundlePath) {
    throw new Error(
      "Usage: npm run verify:bundle -- <proof-bundle.json> [original-file] [encrypted-original.ssenc]",
    );
  }

  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  const receipt = bundle.receipt ?? bundle.record?.receipt;
  const receiptSha256 = bundle.receiptSha256 ?? bundle.record?.receiptSha256;
  if (!receipt || !receiptSha256) {
    throw new Error("The JSON file does not contain a v1.2 receipt and receipt digest.");
  }

  const calculatedReceiptSha256 = sha256(stableStringify(receipt));
  if (calculatedReceiptSha256 !== receiptSha256) {
    throw new Error(
      `Receipt digest mismatch: expected ${receiptSha256}, calculated ${calculatedReceiptSha256}.`,
    );
  }

  console.log(`Receipt integrity: PASS (${receipt.recordId})`);
  console.log(`Receipt time: ${receipt.receivedAt}`);
  console.log("Qualified timestamp: NOT ISSUED in v1.2");
  console.log("Public-chain anchor: NOT ANCHORED in v1.2");

  if (originalPath) {
    const original = await readFile(originalPath);
    const calculatedFileSha256 = sha256(original);
    if (calculatedFileSha256 !== receipt.recordSha256) {
      throw new Error(
        `File digest mismatch for ${path.basename(originalPath)}: expected ${receipt.recordSha256}, calculated ${calculatedFileSha256}.`,
      );
    }
    console.log(`Original file integrity: PASS (${path.basename(originalPath)})`);
  } else {
    console.log("Original file integrity: NOT CHECKED (no file supplied)");
  }

  if (encryptedOriginalPath) {
    const expectedCipherSha256 =
      receipt.encryptedOriginal?.ciphertextSha256 ??
      bundle.encryptedOriginal?.ciphertextSha256;
    if (!expectedCipherSha256) {
      throw new Error("The receipt does not contain an encrypted-original digest.");
    }
    const encryptedOriginal = await readFile(encryptedOriginalPath);
    const calculatedCipherSha256 = sha256(encryptedOriginal);
    if (calculatedCipherSha256 !== expectedCipherSha256) {
      throw new Error(
        `Encrypted-original digest mismatch for ${path.basename(encryptedOriginalPath)}: expected ${expectedCipherSha256}, calculated ${calculatedCipherSha256}.`,
      );
    }
    console.log(
      `Encrypted-original integrity: PASS (${path.basename(encryptedOriginalPath)})`,
    );
  } else {
    console.log(
      "Encrypted-original integrity: NOT CHECKED (no ciphertext supplied)",
    );
  }
}

main().catch((error) => {
  console.error(`Verification failed: ${error.message}`);
  process.exitCode = 1;
});
