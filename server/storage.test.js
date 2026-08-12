import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  createMemoryObjectStore,
  createS3ObjectStore,
  resolveS3Config,
  validateEncryptedUpload,
} from "./storage.js";

const submissionId = "123e4567-e89b-42d3-a456-426614174000";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function uploadFixture() {
  const body = Buffer.from("0123456789abcdef0123456789abcdef");
  const recoveryToken = Buffer.alloc(32, 7);
  const recordSha256 = "a".repeat(64);
  return validateEncryptedUpload({
    submissionId,
    headers: {
      "x-sitesealed-record-sha256": recordSha256,
      "x-sitesealed-cipher-sha256": sha256(body),
      "x-sitesealed-cipher-iv": Buffer.alloc(12, 8).toString("base64"),
      "x-sitesealed-original-bytes": "16",
      "x-sitesealed-recovery-token-sha256": sha256(recoveryToken),
    },
    body,
  });
}

test("the five Railway Bucket references resolve to a virtual-hosted S3 client config", () => {
  const config = resolveS3Config({
    DATABASE_MODE: "required",
    S3_ACCESS_KEY: "access-key-id",
    S3_BUCKET: "sitesealed-production-abc123",
    S3_ENDPOINT: "https://storage.railway.app",
    S3_REGION: "auto",
    S3_SECRET_KEY: "secret-access-key",
  });

  assert.deepEqual(config, {
    accessKeyId: "access-key-id",
    bucket: "sitesealed-production-abc123",
    endpoint: "https://storage.railway.app",
    region: "auto",
    secretAccessKey: "secret-access-key",
    forcePathStyle: false,
  });
});

test("production-required mode refuses missing or partial S3 configuration", () => {
  assert.throws(
    () => resolveS3Config({ DATABASE_MODE: "required" }),
    /five S3 variables are not configured/,
  );
  assert.throws(
    () =>
      resolveS3Config({
        DATABASE_MODE: "optional",
        S3_BUCKET: "partial",
      }),
    /Incomplete S3 configuration/,
  );
  assert.equal(resolveS3Config({ DATABASE_MODE: "optional" }), null);
});

test("encrypted uploads are re-hashed server-side before storage", () => {
  const upload = uploadFixture();
  assert.equal(upload.body.length, upload.plaintextBytes + 16);
  assert.equal(upload.ciphertextSha256, sha256(upload.body));

  assert.throws(
    () =>
      validateEncryptedUpload({
        submissionId,
        headers: {
          "x-sitesealed-record-sha256": upload.recordSha256,
          "x-sitesealed-cipher-sha256": "f".repeat(64),
          "x-sitesealed-cipher-iv": upload.iv,
          "x-sitesealed-original-bytes": "16",
          "x-sitesealed-recovery-token-sha256":
            upload.recoveryTokenSha256,
        },
        body: upload.body,
      }),
    /does not match its declared SHA-256/,
  );
});

test("the memory object store is private, idempotent and integrity checked", async () => {
  const store = createMemoryObjectStore();
  const upload = uploadFixture();
  const first = await store.putEncryptedOriginal(upload);
  const second = await store.putEncryptedOriginal(upload);
  assert.equal(first.created, true);
  assert.equal(second.created, false);
  assert.equal(first.descriptor.objectKey, second.descriptor.objectKey);
  await store.assertStored(first.descriptor, upload);
  assert.deepEqual(
    await store.getEncryptedOriginal(first.descriptor),
    upload.body,
  );
});

test("the S3 adapter writes only ciphertext and verifies object metadata", async () => {
  const upload = uploadFixture();
  let headCount = 0;
  const commands = [];
  const client = {
    async send(command) {
      commands.push(command);
      const name = command.constructor.name;
      if (name === "HeadObjectCommand") {
        headCount += 1;
        if (headCount === 1) {
          const error = new Error("missing");
          error.$metadata = { httpStatusCode: 404 };
          throw error;
        }
        return {
          ContentLength: upload.body.length,
          Metadata: {
            "submission-id": upload.submissionId,
            "record-sha256": upload.recordSha256,
            "cipher-sha256": upload.ciphertextSha256,
            "cipher-iv": upload.iv,
            "original-bytes": String(upload.plaintextBytes),
            "recovery-token-sha256": upload.recoveryTokenSha256,
            encryption: "AES-256-GCM",
            "client-encrypted": "true",
          },
        };
      }
      if (name === "PutObjectCommand") return { ETag: "ciphertext-etag" };
      if (name === "GetObjectCommand") {
        return {
          Body: {
            async transformToByteArray() {
              return Uint8Array.from(upload.body);
            },
          },
        };
      }
      if (name === "HeadBucketCommand") return {};
      throw new Error(`Unexpected command: ${name}`);
    },
    destroy() {},
  };

  const store = createS3ObjectStore({
    client,
    bucket: "private-bucket",
  });
  const stored = await store.putEncryptedOriginal(upload);
  assert.equal(stored.created, true);
  await store.assertStored(stored.descriptor, upload);
  assert.deepEqual(
    await store.getEncryptedOriginal(stored.descriptor),
    upload.body,
  );
  assert.equal((await store.healthCheck()).mode, "s3");

  const put = commands.find(
    (command) => command.constructor.name === "PutObjectCommand",
  );
  assert.equal(put.input.Bucket, "private-bucket");
  assert.deepEqual(Buffer.from(put.input.Body), upload.body);
  assert.equal(put.input.Metadata["client-encrypted"], "true");
  assert.equal(JSON.stringify(put.input).includes("secret-access-key"), false);
});
