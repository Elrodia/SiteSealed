import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createDevelopmentRecord,
  createProofBundle,
  sha256Hex,
  stableStringify,
  validateSealRequest,
} from "./records.js";

function validBody(overrides = {}) {
  const submissionId =
    overrides.submissionId ?? "123e4567-e89b-42d3-a456-426614174000";
  const ciphertextSha256 = "c".repeat(64);
  return {
    submissionId,
    protocolVersion: "1.2",
    recordClass: "IMPORTED_FILE",
    recordSha256: "A".repeat(64),
    manifestSha256: "b".repeat(64),
    encryptedManifest: {
      version: 1,
      algorithm: "AES-256-GCM",
      iv: Buffer.alloc(12, 3).toString("base64"),
      ciphertext: Buffer.alloc(24, 4).toString("base64"),
    },
    encryptedObject: {
      version: 1,
      storageClass: "PRIVATE_CLIENT_ENCRYPTED_ORIGINAL",
      objectKey: `sealed/v1.2/${submissionId}/cc/${ciphertextSha256}.ssenc`,
      algorithm: "AES-256-GCM",
      iv: Buffer.alloc(12, 5).toString("base64"),
      ciphertextSha256,
      ciphertextBytes: 32,
      plaintextBytes: 16,
      recoveryTokenSha256: "d".repeat(64),
    },
    ...overrides,
  };
}

test("canonical JSON ordering makes receipt digests deterministic", () => {
  const first = stableStringify({ z: 1, nested: { b: 2, a: 1 }, a: [3, 2] });
  const second = stableStringify({ a: [3, 2], nested: { a: 1, b: 2 }, z: 1 });
  assert.equal(first, second);
  assert.equal(sha256Hex(first), sha256Hex(second));
});

test("seal request validation normalizes hexadecimal digests", () => {
  const validated = validateSealRequest(validBody());
  assert.equal(validated.recordSha256, "a".repeat(64));
  assert.equal(validated.manifestSha256, "b".repeat(64));
  assert.equal(validated.encryptedManifest.algorithm, "AES-256-GCM");
  assert.equal(validated.encryptedObject.ciphertextSha256, "c".repeat(64));
});

test("seal request validation rejects noncanonical or oversized envelopes", () => {
  assert.throws(
    () => validateSealRequest(validBody({ recordSha256: "not-a-digest" })),
    /64-character hexadecimal/,
  );
  assert.throws(
    () =>
      validateSealRequest(
        validBody({
          encryptedManifest: {
            version: 1,
            algorithm: "AES-256-GCM",
            iv: Buffer.alloc(11).toString("base64"),
            ciphertext: Buffer.alloc(24).toString("base64"),
          },
        }),
      ),
    /exactly 12 bytes/,
  );
});

test("development receipt and exported bundle agree cryptographically", () => {
  const input = validateSealRequest(validBody());
  const record = createDevelopmentRecord(input, {
    recordId: "SR-20260811-ABCDEF0123456789ABCDEF01",
    receivedAt: new Date("2026-08-11T21:00:00.000Z"),
  });
  const bundle = createProofBundle(record, input.encryptedManifest);

  assert.equal(record.receiptSha256, sha256Hex(stableStringify(record.receipt)));
  assert.equal(bundle.receiptSha256, record.receiptSha256);
  assert.equal(bundle.record.recordSha256, record.sha256);
  assert.equal(bundle.encryptedOriginal.state, "STORED_ENCRYPTED");
  assert.equal(
    record.receipt.encryptedOriginal.ciphertextSha256,
    input.encryptedObject.ciphertextSha256,
  );
  assert.equal(bundle.proofs.qualifiedTimestamp.state, "NOT_ISSUED");
  assert.equal(bundle.proofs.publicChain.state, "NOT_ANCHORED");
});
