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
      "content-length": String(body.length),
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
          "content-length": String(upload.body.length),
        },
        body: upload.body,
      }),
    /does not match its declared SHA-256/,
  );
});

test("the memory object store is private, idempotent and integrity checked", async () => {
  const store = createMemoryObjectStore();
  const upload = uploadFixture();
  const first = await store.putStagedEncryptedOriginal(upload);
  const second = await store.putStagedEncryptedOriginal(upload);
  assert.equal(first.created, true);
  assert.equal(second.created, false);
  assert.equal(first.descriptor.objectKey, second.descriptor.objectKey);
  await assert.rejects(store.getEncryptedOriginal(first.descriptor));
  const promoted = await store.promoteEncryptedOriginal(
    first.descriptor,
    upload,
  );
  assert.equal(promoted.created, true);
  assert.deepEqual(
    await store.getEncryptedOriginal(first.descriptor),
    upload.body,
  );
  await store.discardStagedEncryptedOriginal(first.descriptor, upload);
});

test("the S3 adapter writes only ciphertext and verifies object metadata", async () => {
  const upload = uploadFixture();
  const commands = [];
  const objects = new Map();
  const metadata = {
    "submission-id": upload.submissionId,
    "record-sha256": upload.recordSha256,
    "cipher-sha256": upload.ciphertextSha256,
    "cipher-iv": upload.iv,
    "original-bytes": String(upload.plaintextBytes),
    "recovery-token-sha256": upload.recoveryTokenSha256,
    encryption: "AES-256-GCM",
    "client-encrypted": "true",
  };
  const client = {
    async send(command) {
      commands.push(command);
      const name = command.constructor.name;
      if (name === "HeadObjectCommand") {
        const stored = objects.get(command.input.Key);
        if (!stored) {
          const error = new Error("missing");
          error.$metadata = { httpStatusCode: 404 };
          throw error;
        }
        return {
          ContentLength: stored.body.length,
          Metadata: stored.metadata,
        };
      }
      if (name === "PutObjectCommand") {
        objects.set(command.input.Key, {
          body: Buffer.from(command.input.Body),
          metadata: command.input.Metadata,
        });
        return { ETag: "ciphertext-etag" };
      }
      if (name === "CopyObjectCommand") {
        const sourceKey = decodeURIComponent(
          command.input.CopySource.split("/").slice(1).join("/"),
        );
        const source = objects.get(sourceKey);
        objects.set(command.input.Key, {
          body: Buffer.from(source.body),
          metadata: { ...source.metadata },
        });
        return { CopyObjectResult: { ETag: "copied-etag" } };
      }
      if (name === "DeleteObjectCommand") {
        objects.delete(command.input.Key);
        return {};
      }
      if (name === "GetObjectCommand") {
        const stored = objects.get(command.input.Key);
        return {
          Body: {
            async transformToByteArray() {
              return Uint8Array.from(stored.body);
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
  const stored = await store.putStagedEncryptedOriginal(upload);
  assert.equal(stored.created, true);
  assert.equal(stored.staged, true);
  const stagedPut = commands.find(
    (command) => command.constructor.name === "PutObjectCommand",
  );
  assert.match(stagedPut.input.Key, /^staging\/v1\.2\//);
  await store.promoteEncryptedOriginal(stored.descriptor, upload);
  assert.deepEqual(
    await store.getEncryptedOriginal(stored.descriptor),
    upload.body,
  );
  await store.discardStagedEncryptedOriginal(stored.descriptor, upload);
  assert.equal((await store.healthCheck()).mode, "s3");

  const copy = commands.find(
    (command) => command.constructor.name === "CopyObjectCommand",
  );
  assert.match(copy.input.Key, /^sealed\/v1\.2\//);
  assert.equal(stagedPut.input.Bucket, "private-bucket");
  assert.deepEqual(Buffer.from(stagedPut.input.Body), upload.body);
  assert.deepEqual(stagedPut.input.Metadata, metadata);
  assert.equal(
    JSON.stringify(stagedPut.input).includes("secret-access-key"),
    false,
  );
});

test("the application reaper deletes only expired staging objects", async () => {
  let timestamp = Date.parse("2026-08-13T12:00:00.000Z");
  const store = createMemoryObjectStore({ now: () => timestamp });
  const oldUpload = uploadFixture();
  await store.putStagedEncryptedOriginal(oldUpload);
  timestamp += 25 * 60 * 60 * 1000;
  const result = await store.cleanupStagedObjects({
    olderThan: new Date(timestamp - 24 * 60 * 60 * 1000),
  });
  assert.equal(result.deleted, 1);
  assert.equal(result.deletedBytes, oldUpload.body.length);
});
