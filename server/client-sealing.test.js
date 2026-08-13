import assert from "node:assert/strict";
import { File } from "node:buffer";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { gcm } from "@noble/ciphers/aes.js";
import {
  buildManifest,
  createEncryptedUploadHeaders,
  createRecoveryToken,
  createSealRequest,
  createUploadGrantRequest,
  encryptManifest,
  encryptOriginal,
  recalculateEvidenceDigest,
  sha256File,
  stableStringify,
  verifyPublicProofArtifacts,
} from "../client/src/sealing.js";
import { buildMerkleTree } from "./merkle.js";
import { createEvidenceDigest } from "./records.js";

function fromBase64(value) {
  return Uint8Array.from(Buffer.from(value, "base64"));
}

test("the browser workflow hashes the selected file locally", async () => {
  const file = new File(["abc"], "inspection.txt", {
    type: "text/plain",
    lastModified: Date.parse("2026-08-11T20:00:00.000Z"),
  });
  const digest = await sha256File(file);
  assert.equal(
    digest,
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("the client encrypts the canonical manifest and keeps the key outside the API request", async () => {
  const file = new File(["construction record"], "IMG_0001.JPG", {
    type: "image/jpeg",
    lastModified: Date.parse("2026-08-11T20:00:00.000Z"),
  });
  const manifest = buildManifest(file, {
    projectReference: "RBP-C-2026",
    description: "Foundation inspection",
  });
  const encrypted = await encryptManifest(manifest);
  const encryptedFile = await encryptOriginal(file, encrypted.recoveryKey);
  const recoveryToken = await createRecoveryToken();
  const encryptedObject = {
    ...encryptedFile.envelope,
    objectKey:
      `sealed/v1.2/123e4567-e89b-42d3-a456-426614174000/` +
      `${encryptedFile.envelope.ciphertextSha256.slice(0, 2)}/` +
      `${encryptedFile.envelope.ciphertextSha256}.ssenc`,
    recoveryTokenSha256: recoveryToken.sha256,
  };
  const request = createSealRequest({
    recordSha256: await sha256File(file),
    manifestSha256: encrypted.manifestSha256,
    envelope: encrypted.envelope,
    encryptedObject,
    submissionId: "123e4567-e89b-42d3-a456-426614174000",
  });

  assert.equal(Object.hasOwn(request, "recoveryKey"), false);
  assert.equal(JSON.stringify(request).includes("Foundation inspection"), false);
  assert.equal(request.encryptedManifest.algorithm, "AES-256-GCM");
  assert.equal(request.encryptedObject.algorithm, "AES-256-GCM");

  const key = await crypto.subtle.importKey(
    "raw",
    fromBase64(encrypted.recoveryKey),
    "AES-GCM",
    false,
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(encrypted.envelope.iv) },
    key,
    fromBase64(encrypted.envelope.ciphertext),
  );
  assert.equal(new TextDecoder().decode(plaintext), stableStringify(manifest));

  const originalPlaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(encryptedFile.envelope.iv) },
    key,
    encryptedFile.ciphertext,
  );
  assert.equal(
    new TextDecoder().decode(originalPlaintext),
    "construction record",
  );
  assert.equal(encryptedFile.ciphertext.length, file.size + 16);

  const headers = createEncryptedUploadHeaders({
    recordSha256: request.recordSha256,
    encryptedOriginal: encryptedFile,
    recoveryTokenSha256: recoveryToken.sha256,
    uploadGrant: "grant-token",
  });
  assert.equal(headers["content-type"], "application/octet-stream");
  assert.equal(
    headers["x-sitesealed-cipher-sha256"],
    encryptedFile.envelope.ciphertextSha256,
  );
  assert.equal(headers["x-sitesealed-upload-grant"], "grant-token");
  assert.deepEqual(
    createUploadGrantRequest({
      submissionId: request.submissionId,
      recordSha256: request.recordSha256,
      encryptedOriginal: encryptedFile,
      recoveryTokenSha256: recoveryToken.sha256,
    }),
    {
      submissionId: request.submissionId,
      recordSha256: request.recordSha256,
      ciphertextSha256: encryptedFile.envelope.ciphertextSha256,
      ciphertextBytes: encryptedFile.envelope.ciphertextBytes,
      plaintextBytes: encryptedFile.envelope.plaintextBytes,
      iv: encryptedFile.envelope.iv,
      recoveryTokenSha256: recoveryToken.sha256,
    },
  );
  assert.equal(JSON.stringify(request).includes(recoveryToken.token), false);
});

test("the local cryptography fallback works outside a secure Web Crypto context", async () => {
  const originalCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: {
      getRandomValues: originalCrypto.getRandomValues.bind(originalCrypto),
    },
  });

  try {
    const file = new File(["fallback"], "fallback.txt", {
      type: "text/plain",
      lastModified: Date.parse("2026-08-11T20:00:00.000Z"),
    });
    assert.equal(
      await sha256File(file),
      "5c7ee2074b65853f71fc5a01ce194ff26deedf6daacdb715c6beefdfd3f31b35",
    );

    const manifest = buildManifest(file, {
      projectReference: "FALLBACK-QA",
      description: "No subtle crypto available",
    });
    const encrypted = await encryptManifest(manifest);
    const plaintext = gcm(
      fromBase64(encrypted.recoveryKey),
      fromBase64(encrypted.envelope.iv),
    ).decrypt(fromBase64(encrypted.envelope.ciphertext));
    assert.equal(new TextDecoder().decode(plaintext), stableStringify(manifest));
  } finally {
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: originalCrypto,
    });
  }
});

test("the browser independently recalculates the evidence digest and Ethereum Merkle binding", async () => {
  const recordSha256 =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  const manifestSha256 = "1".repeat(64);
  const evidenceDigest = createEvidenceDigest({
    recordSha256,
    manifestSha256,
  });
  assert.equal(
    await recalculateEvidenceDigest(recordSha256, manifestSha256),
    evidenceDigest,
  );

  const tree = buildMerkleTree([
    { recordId: "SR-BROWSER-1", evidenceDigest },
    { recordId: "SR-BROWSER-2", evidenceDigest: "2".repeat(64) },
  ]);
  const member = tree.members[0];
  const record = {
    sha256: recordSha256,
    manifestSha256,
    evidenceDigest,
    receipt: { schemaVersion: "sitesealed.receipt.v1.4-alpha.1" },
    chainRail: {
      anchor: `0x${"3".repeat(64)}`,
      chainId: 1,
      merkleRoot: tree.root,
      leafHash: member.leafHash,
      inclusionPath: member.inclusionPath,
      transactionInput: `0x53534c4401${tree.root}`,
    },
  };

  assert.deepEqual(await verifyPublicProofArtifacts(record), {
    state: "PASS",
    evidenceDigest: "PASS",
    merkleInclusion: "PASS",
    transactionBinding: "PASS",
  });

  record.chainRail.transactionInput = `0x53534c4401${"f".repeat(64)}`;
  assert.deepEqual(await verifyPublicProofArtifacts(record), {
    state: "FAIL",
    evidenceDigest: "PASS",
    merkleInclusion: "PASS",
    transactionBinding: "MISMATCH",
  });

  delete record.chainRail.transactionInput;
  assert.deepEqual(await verifyPublicProofArtifacts(record), {
    state: "FAIL",
    evidenceDigest: "PASS",
    merkleInclusion: "PASS",
    transactionBinding: "MISSING",
  });
});

test("the browser reports a valid local receipt while its external anchor is pending", async () => {
  const recordSha256 = "4".repeat(64);
  const manifestSha256 = "5".repeat(64);
  const record = {
    sha256: recordSha256,
    manifestSha256,
    evidenceDigest: createEvidenceDigest({ recordSha256, manifestSha256 }),
    receipt: { schemaVersion: "sitesealed.receipt.v1.4-alpha.1" },
    chainRail: { anchor: null, merkleRoot: null, inclusionPath: null },
  };

  assert.deepEqual(await verifyPublicProofArtifacts(record), {
    state: "RECEIPT_VALID_EXTERNAL_PENDING",
    evidenceDigest: "PASS",
    merkleInclusion: "NOT_ATTACHED",
    transactionBinding: "NOT_ATTACHED",
  });
});

test("the browser uses Google Identity Services and sends SiteSealed CSRF tokens", async () => {
  const source = await readFile(
    new URL("../client/src/App.jsx", import.meta.url),
    "utf8",
  );
  const desktopStyles = await readFile(
    new URL("../client/src/App-desktop.css", import.meta.url),
    "utf8",
  );
  assert.match(source, /google\.accounts\.id\.renderButton/);
  assert.match(source, /ux_mode: "redirect"/);
  assert.match(source, /type: "icon"/);
  assert.match(source, /theme: "outline_dark"/);
  assert.match(source, /size: "small"/);
  assert.doesNotMatch(source, /width: 240/);
  assert.match(
    desktopStyles,
    /\.account-access\s*\{[^}]*background: #0d2232;/s,
  );
  assert.match(
    desktopStyles,
    /\.google-signin-button\s*\{[^}]*width: 32px;[^}]*height: 32px;[^}]*overflow: hidden;/s,
  );
  assert.doesNotMatch(desktopStyles, /img,\s*\nsvg\s*\{/);
  assert.match(source, /"x-sitesealed-csrf": auth\.csrfToken/);
  assert.doesNotMatch(source, /x-sitesealed-deposit-access/);
  assert.doesNotMatch(source, /depositAccess/);
});
