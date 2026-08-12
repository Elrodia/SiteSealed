import assert from "node:assert/strict";
import { File } from "node:buffer";
import { test } from "node:test";
import { gcm } from "@noble/ciphers/aes.js";
import {
  buildManifest,
  createEncryptedUploadHeaders,
  createRecoveryToken,
  createSealRequest,
  encryptManifest,
  encryptOriginal,
  sha256File,
  stableStringify,
} from "../client/src/sealing.js";

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
  });
  assert.equal(headers["content-type"], "application/octet-stream");
  assert.equal(
    headers["x-sitesealed-cipher-sha256"],
    encryptedFile.envelope.ciphertextSha256,
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
