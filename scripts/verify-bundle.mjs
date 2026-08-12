import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { JsonRpcProvider, WebSocketProvider } from "ethers";
import { verifyRfc3161Token } from "../server/rfc3161.js";

const ANCHOR_CALLDATA_MAGIC = "53534c4401";

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

function merkleLeafHash(evidenceDigest) {
  return sha256(
    Buffer.concat([Buffer.from([0]), Buffer.from(evidenceDigest, "hex")]),
  );
}

function merkleParentHash(left, right) {
  return sha256(
    Buffer.concat([
      Buffer.from([1]),
      Buffer.from(left, "hex"),
      Buffer.from(right, "hex"),
    ]),
  );
}

async function verifyEthereumTransaction(chain) {
  const rpcValue = String(process.env.ETHEREUM_VERIFY_RPC_URL ?? "").trim();
  if (!rpcValue) {
    console.log(
      "Ethereum transaction binding: NOT CHECKED (set ETHEREUM_VERIFY_RPC_URL to an independent mainnet RPC)",
    );
    return;
  }
  const rpcUrl = new URL(rpcValue);
  if (!["https:", "wss:"].includes(rpcUrl.protocol)) {
    throw new Error("ETHEREUM_VERIFY_RPC_URL must use HTTPS or WSS.");
  }
  const provider = rpcUrl.protocol === "wss:"
    ? new WebSocketProvider(rpcUrl.toString(), 1, { staticNetwork: true })
    : new JsonRpcProvider(rpcUrl.toString(), 1, { staticNetwork: true });
  try {
    const network = await provider.getNetwork();
    if (Number(network.chainId) !== 1) {
      throw new Error(`The verification RPC returned chain ${network.chainId}, not Ethereum mainnet.`);
    }
    if (!/^0x[a-f0-9]{64}$/i.test(String(chain.transaction ?? ""))) {
      throw new Error("The bundle has no valid Ethereum transaction hash.");
    }
    const [transaction, receipt, finalizedBlock] = await Promise.all([
      provider.getTransaction(chain.transaction),
      provider.getTransactionReceipt(chain.transaction),
      provider.getBlock("finalized").catch(() => null),
    ]);
    if (!transaction || !receipt || Number(receipt.status) !== 1) {
      throw new Error("The Ethereum anchor transaction is absent, pending or failed.");
    }
    const expectedInput = `0x${ANCHOR_CALLDATA_MAGIC}${chain.merkleRoot}`;
    if (String(transaction.data).toLowerCase() !== expectedInput.toLowerCase()) {
      throw new Error("The Ethereum transaction calldata does not contain this Merkle root.");
    }
    if (
      !chain.anchorAddress ||
      String(transaction.from).toLowerCase() !== String(chain.anchorAddress).toLowerCase() ||
      String(transaction.to).toLowerCase() !== String(chain.anchorAddress).toLowerCase()
    ) {
      throw new Error("The Ethereum sender or destination does not match the bundle.");
    }
    if (chain.blockHash && String(receipt.blockHash).toLowerCase() !== String(chain.blockHash).toLowerCase()) {
      throw new Error("The Ethereum block hash does not match the bundle.");
    }
    const finalized = Boolean(
      finalizedBlock && Number(receipt.blockNumber) <= Number(finalizedBlock.number),
    );
    if (chain.state === "FINALIZED" && !finalized) {
      throw new Error("The bundle claims finality but the independent RPC does not.");
    }
    console.log(
      `Ethereum transaction binding: PASS (block ${receipt.blockNumber}, finalized: ${finalized ? "YES" : "NO"})`,
    );
  } finally {
    await provider.destroy();
  }
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
    throw new Error("The JSON file does not contain a SiteSealed receipt and receipt digest.");
  }

  const calculatedReceiptSha256 = sha256(stableStringify(receipt));
  if (calculatedReceiptSha256 !== receiptSha256) {
    throw new Error(
      `Receipt digest mismatch: expected ${receiptSha256}, calculated ${calculatedReceiptSha256}.`,
    );
  }

  console.log(`Receipt integrity: PASS (${receipt.recordId})`);
  console.log(`Receipt time: ${receipt.receivedAt}`);
  const timestamp = bundle.proofs?.qualifiedTimestamp;
  if (timestamp?.state === "SANDBOX_TOKEN_ISSUED") {
    if (timestamp.hashedMessage !== receipt.evidenceDigest) {
      throw new Error("The Evidency timestamp response is bound to another evidence digest.");
    }
    const tokenBytes = Buffer.from(timestamp.token?.value ?? "", "base64");
    if (
      tokenBytes.length < 16 ||
      sha256(tokenBytes) !== timestamp.token?.sha256
    ) {
      throw new Error("The exported Evidency timestamp token digest is invalid.");
    }
    const verification = await verifyRfc3161Token({
      token: tokenBytes,
      expectedDigest: receipt.evidenceDigest,
      expectedSerialNumber: timestamp.serialNumber,
      expectedCertifiedAt: timestamp.certifiedAt,
      expectedPolicyId: timestamp.tsaPolicyId,
    });
    console.log(`RFC 3161 timestamp: PASS (${verification.serialNumber})`);
    console.log(
      `CMS signature: ${verification.signatureVerification} (${verification.cmsSignatureAlgorithm})`,
    );
    console.log(
      `Certificate path: ${verification.certificateChainVerification} (${verification.certificatePathLength} certificates)`,
    );
    console.log(
      `Signer binding: ${verification.signingCertificateVerification}; revocation: ${verification.revocationVerification}`,
    );
    console.log("Legal qualification: TEST ONLY - NOT QUALIFIED");
  } else {
    console.log("RFC 3161 timestamp: NOT ISSUED");
  }

  const chain = bundle.proofs?.publicChain;
  if (chain?.merkleRoot && Array.isArray(chain.inclusionPath)) {
    let calculatedRoot = merkleLeafHash(receipt.evidenceDigest);
    for (const step of chain.inclusionPath) {
      calculatedRoot =
        step.position === "left"
          ? merkleParentHash(step.sha256, calculatedRoot)
          : merkleParentHash(calculatedRoot, step.sha256);
    }
    if (calculatedRoot !== chain.merkleRoot) {
      throw new Error("The Ethereum Merkle inclusion path is invalid.");
    }
    console.log(`Merkle inclusion: PASS (${chain.merkleRoot})`);
    console.log(
      `Public-chain anchor: ${chain.state} (${chain.transaction ?? "transaction pending"})`,
    );
    if (chain.transaction) await verifyEthereumTransaction(chain);
  } else {
    console.log("Public-chain anchor: NOT ANCHORED");
  }

  const audit = bundle.operationalAudit;
  if (audit?.state === "RECORDED" && audit.event) {
    const payloadSha256 = sha256(stableStringify(audit.event.payload));
    const auditPreimage = {
      schemaVersion: audit.event.schemaVersion,
      eventId: audit.event.eventId,
      eventType: audit.event.eventType,
      recordId: audit.event.recordId,
      payloadSha256: audit.event.payloadSha256,
      previousEventSha256: audit.event.previousEventSha256 ?? null,
      recordedAt: audit.event.recordedAt,
    };
    const eventSha256 = sha256(stableStringify(auditPreimage));
    if (
      payloadSha256 !== audit.event.payloadSha256 ||
      eventSha256 !== audit.event.eventSha256
    ) {
      throw new Error("The PostgreSQL operational-audit event hash is invalid.");
    }
    console.log(
      `Operational audit event: PASS (internal hash chain sequence ${audit.event.sequence})`,
    );
    console.log("Operational audit independence: NO - application database only");
  } else {
    console.log(`Operational audit event: ${audit?.state ?? "NOT PROVIDED"}`);
  }

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
