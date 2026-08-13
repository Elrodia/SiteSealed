import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { test } from "node:test";
import {
  createMemoryCoordinator,
  createRedisCoordinator,
  UPLOAD_GRANT_TTL_MS,
} from "./coordination.js";
import {
  createMemoryObjectStore,
  createS3ObjectStore,
  resolveS3Config,
  validateEncryptedUpload,
  validateUploadGrantRequest,
} from "./storage.js";

const submissionId = "123e4567-e89b-42d3-a456-426614174000";
const otherSubmissionId = "123e4567-e89b-42d3-a456-426614174001";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function createFakeRedisClient() {
  const entries = new Map();
  const live = (key) => {
    const entry = entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      entries.delete(key);
      return null;
    }
    return entry;
  };
  return {
    async set(key, value, options = {}) {
      if (options.NX && live(key)) return null;
      entries.set(key, {
        value: String(value),
        expiresAt: Date.now() + Number(options.PX ?? 60_000),
      });
      return "OK";
    },
    async get(key) {
      return live(key)?.value ?? null;
    },
    async del(key) {
      return entries.delete(key) ? 1 : 0;
    },
  };
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

test("upload grant requests reuse the shared submission, digest and size validators", () => {
  const body = Buffer.from("0123456789abcdef0123456789abcdef");
  assert.deepEqual(
    validateUploadGrantRequest({
      submissionId: submissionId.toUpperCase(),
      ciphertextSha256: sha256(body).toUpperCase(),
      byteLength: body.length,
    }),
    {
      submissionId,
      ciphertextSha256: sha256(body),
      byteLength: body.length,
    },
  );

  assert.throws(
    () =>
      validateUploadGrantRequest({
        submissionId,
        ciphertextSha256: sha256(body),
        byteLength: body.length,
        originalBase64: "do-not-accept",
      }),
    /must never be sent/,
  );
  assert.throws(
    () =>
      validateUploadGrantRequest({
        submissionId: "not-a-uuid",
        ciphertextSha256: sha256(body),
        byteLength: body.length,
      }),
    /submissionId must be a random UUID v4/,
  );
  assert.throws(
    () =>
      validateUploadGrantRequest({
        submissionId,
        ciphertextSha256: "zz",
        byteLength: body.length,
      }),
    /ciphertextSha256 must be a 64-character hexadecimal/,
  );
  assert.throws(
    () =>
      validateUploadGrantRequest({
        submissionId,
        ciphertextSha256: sha256(body),
        byteLength: 25 * 1024 * 1024 + 17,
      }),
    /byteLength must be a positive integer/,
  );
  assert.throws(
    () =>
      validateUploadGrantRequest({
        submissionId,
        ciphertextSha256: sha256(body),
        byteLength: 0,
      }),
    /byteLength must be a positive integer/,
  );
});

async function uploadGrantScenario(coordinator) {
  const body = Buffer.from("0123456789abcdef0123456789abcdef");
  const otherBody = Buffer.from("fedcba9876543210fedcba9876543210");
  const binding = {
    submissionId,
    ciphertextSha256: sha256(body),
    byteLength: body.length,
  };
  const outcome = [];

  const grant = await coordinator.issueUploadGrant(binding);
  outcome.push(`format:${/^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/.test(grant.grantId)}`);
  outcome.push(`ttl:${Date.parse(grant.expiresAt) - Date.now() > 14 * 60 * 1000}`);

  outcome.push(`unknown:${await coordinator.openUploadGrant(`${crypto.randomUUID()}.${"a".repeat(43)}`, binding)}`);
  outcome.push(`malformed:${await coordinator.openUploadGrant("not-a-grant", binding)}`);
  outcome.push(
    `tampered:${await coordinator.openUploadGrant(
      `${grant.grantId.split(".")[0]}.${"b".repeat(43)}`,
      binding,
    )}`,
  );
  outcome.push(
    `submission:${await coordinator.openUploadGrant(grant.grantId, {
      ...binding,
      submissionId: otherSubmissionId,
    })}`,
  );
  outcome.push(
    `digest:${await coordinator.openUploadGrant(grant.grantId, {
      ...binding,
      ciphertextSha256: sha256(otherBody),
    })}`,
  );
  outcome.push(
    `size:${await coordinator.openUploadGrant(grant.grantId, {
      ...binding,
      byteLength: body.length + 1,
    })}`,
  );

  const opened = await coordinator.openUploadGrant(grant.grantId, binding);
  outcome.push(`opened:${opened.consumed}`);
  outcome.push(`consume:${await opened.consume()}`);
  outcome.push(`consumeTwice:${await opened.consume()}`);

  const replayed = await coordinator.openUploadGrant(grant.grantId, binding);
  outcome.push(`replayConsumed:${replayed.consumed}`);
  outcome.push(
    `replayOtherCiphertext:${await coordinator.openUploadGrant(grant.grantId, {
      ...binding,
      ciphertextSha256: sha256(otherBody),
      byteLength: otherBody.length,
    })}`,
  );

  const expiring = await coordinator.issueUploadGrant(binding, { ttlMs: 20 });
  await sleep(60);
  outcome.push(`expired:${await coordinator.openUploadGrant(expiring.grantId, binding)}`);

  return outcome;
}

test("the memory and Redis adapters enforce identical single-use upload grants", async () => {
  const memory = await uploadGrantScenario(createMemoryCoordinator());
  const redis = await uploadGrantScenario(
    createRedisCoordinator(createFakeRedisClient()),
  );

  assert.deepEqual(memory, [
    "format:true",
    "ttl:true",
    "unknown:null",
    "malformed:null",
    "tampered:null",
    "submission:null",
    "digest:null",
    "size:null",
    "opened:false",
    "consume:true",
    "consumeTwice:false",
    "replayConsumed:true",
    "replayOtherCiphertext:null",
    "expired:null",
  ]);
  assert.deepEqual(redis, memory);
  assert.equal(UPLOAD_GRANT_TTL_MS, 15 * 60 * 1000);
});
