import {
  CopyObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { createHash, randomUUID } from "node:crypto";
import {
  ApiError,
  MAX_ENCRYPTED_ORIGINAL_BYTES,
  MAX_ORIGINAL_BYTES,
  decodeCanonicalBase64,
  normalizeDigest,
  normalizeSubmissionId,
  validateEncryptedObjectDescriptor,
} from "./records.js";

const S3_CONFIG_KEYS = [
  "S3_ACCESS_KEY",
  "S3_BUCKET",
  "S3_ENDPOINT",
  "S3_REGION",
  "S3_SECRET_KEY",
];
const STAGING_PREFIX = "staging/v1.2/";
const SEALED_PREFIX = "sealed/v1.2/";
const UPLOAD_BINDING_FIELDS = new Set([
  "submissionId",
  "recordSha256",
  "ciphertextSha256",
  "ciphertextBytes",
  "plaintextBytes",
  "iv",
  "recoveryTokenSha256",
]);

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isNotFound(error) {
  return (
    error?.name === "NotFound" ||
    error?.name === "NoSuchKey" ||
    error?.$metadata?.httpStatusCode === 404
  );
}

function normalizedMetadata(metadata = {}) {
  return Object.fromEntries(
    Object.entries(metadata).map(([key, value]) => [
      key.toLowerCase(),
      String(value),
    ]),
  );
}

function sealedObjectKey(upload) {
  return (
    `${SEALED_PREFIX}${upload.submissionId}/${upload.ciphertextSha256.slice(0, 2)}/` +
    `${upload.ciphertextSha256}.ssenc`
  );
}

function stagingObjectKey(upload) {
  return (
    `${STAGING_PREFIX}${upload.submissionId}/${upload.ciphertextSha256.slice(0, 2)}/` +
    `${upload.ciphertextSha256}.ssenc`
  );
}

function descriptorFromUpload(upload) {
  const objectKey =
    sealedObjectKey(upload);
  return {
    version: 1,
    storageClass: "PRIVATE_CLIENT_ENCRYPTED_ORIGINAL",
    objectKey,
    algorithm: "AES-256-GCM",
    iv: upload.iv,
    ciphertextSha256: upload.ciphertextSha256,
    ciphertextBytes: upload.body.length,
    plaintextBytes: upload.plaintextBytes,
    recoveryTokenSha256: upload.recoveryTokenSha256,
  };
}

function storageMetadata(upload) {
  return {
    "submission-id": upload.submissionId,
    "record-sha256": upload.recordSha256,
    "cipher-sha256": upload.ciphertextSha256,
    "cipher-iv": upload.iv,
    "original-bytes": String(upload.plaintextBytes),
    "recovery-token-sha256": upload.recoveryTokenSha256,
    encryption: "AES-256-GCM",
    "client-encrypted": "true",
  };
}

function assertStoredMetadata(head, descriptor, input) {
  const metadata = normalizedMetadata(head.Metadata);
  const expected = {
    "submission-id": input.submissionId,
    "record-sha256": input.recordSha256,
    "cipher-sha256": descriptor.ciphertextSha256,
    "cipher-iv": descriptor.iv,
    "original-bytes": String(descriptor.plaintextBytes),
    "recovery-token-sha256": descriptor.recoveryTokenSha256,
    encryption: "AES-256-GCM",
    "client-encrypted": "true",
  };
  const mismatch = Object.entries(expected).find(
    ([key, value]) => metadata[key] !== value,
  );
  if (
    mismatch ||
    Number(head.ContentLength) !== descriptor.ciphertextBytes
  ) {
    throw new ApiError(
      409,
      "STORAGE_OBJECT_MISMATCH",
      "The private object does not match the encrypted original descriptor.",
    );
  }
}

function positiveIntegerHeader(value, fieldName, maximum) {
  const text = String(value ?? "").trim();
  if (!/^[1-9][0-9]*$/.test(text)) {
    throw new ApiError(400, "INVALID_UPLOAD_METADATA", `${fieldName} must be a positive integer.`);
  }
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) {
    throw new ApiError(
      400,
      "INVALID_UPLOAD_METADATA",
      `${fieldName} exceeds the v1.4 limit of ${maximum} bytes.`,
    );
  }
  return parsed;
}

function positiveIntegerValue(value, fieldName, maximum) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new ApiError(
      400,
      "INVALID_UPLOAD_GRANT_REQUEST",
      `${fieldName} must be a positive integer no greater than ${maximum}.`,
    );
  }
  return value;
}

function canonicalIv(value, fieldName) {
  const iv = String(value ?? "").trim();
  if (decodeCanonicalBase64(iv, fieldName).length !== 12) {
    throw new ApiError(
      400,
      "INVALID_UPLOAD_METADATA",
      `${fieldName} must contain exactly 12 bytes.`,
    );
  }
  return iv;
}

function bindingFromValues({
  submissionId,
  recordSha256,
  ciphertextSha256,
  ciphertextBytes,
  plaintextBytes,
  iv,
  recoveryTokenSha256,
}) {
  const normalizedPlaintextBytes = positiveIntegerValue(
    plaintextBytes,
    "plaintextBytes",
    MAX_ORIGINAL_BYTES,
  );
  const normalizedCiphertextBytes = positiveIntegerValue(
    ciphertextBytes,
    "ciphertextBytes",
    MAX_ENCRYPTED_ORIGINAL_BYTES,
  );
  if (normalizedCiphertextBytes !== normalizedPlaintextBytes + 16) {
    throw new ApiError(
      400,
      "INVALID_UPLOAD_LENGTH",
      "The encrypted original must be exactly 16 bytes longer than the plaintext size.",
    );
  }
  return {
    submissionId: normalizeSubmissionId(submissionId),
    recordSha256: normalizeDigest(recordSha256, "recordSha256"),
    ciphertextSha256: normalizeDigest(
      ciphertextSha256,
      "ciphertextSha256",
    ),
    ciphertextBytes: normalizedCiphertextBytes,
    plaintextBytes: normalizedPlaintextBytes,
    iv: canonicalIv(iv, "iv"),
    recoveryTokenSha256: normalizeDigest(
      recoveryTokenSha256,
      "recoveryTokenSha256",
    ),
  };
}

export function validateUploadGrantRequest(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiError(
      400,
      "INVALID_UPLOAD_GRANT_REQUEST",
      "The upload grant request must contain the exact encrypted-object binding.",
    );
  }
  const unknown = Object.keys(value).find(
    (field) => !UPLOAD_BINDING_FIELDS.has(field),
  );
  if (unknown) {
    throw new ApiError(
      400,
      "INVALID_UPLOAD_GRANT_REQUEST",
      `Unexpected upload grant field: ${unknown}.`,
    );
  }
  return bindingFromValues(value);
}

export function validateEncryptedUploadHeaders({ submissionId, headers }) {
  const plaintextBytes = positiveIntegerHeader(
    headers["x-sitesealed-original-bytes"],
    "x-sitesealed-original-bytes",
    MAX_ORIGINAL_BYTES,
  );
  const ciphertextBytes = positiveIntegerHeader(
    headers["content-length"],
    "content-length",
    MAX_ENCRYPTED_ORIGINAL_BYTES,
  );
  return bindingFromValues({
    submissionId,
    recordSha256: headers["x-sitesealed-record-sha256"],
    ciphertextSha256: headers["x-sitesealed-cipher-sha256"],
    ciphertextBytes,
    plaintextBytes,
    iv: headers["x-sitesealed-cipher-iv"],
    recoveryTokenSha256:
      headers["x-sitesealed-recovery-token-sha256"],
  });
}

export function validateEncryptedUpload({ submissionId, headers, body }) {
  const binding = validateEncryptedUploadHeaders({ submissionId, headers });
  if (!Buffer.isBuffer(body) || body.length === 0) {
    throw new ApiError(
      400,
      "EMPTY_ENCRYPTED_UPLOAD",
      "The encrypted original payload is empty.",
    );
  }
  if (body.length > MAX_ENCRYPTED_ORIGINAL_BYTES) {
    throw new ApiError(
      413,
      "ENCRYPTED_UPLOAD_TOO_LARGE",
      "The encrypted original exceeds the v1.4 limit of 25 MB plus its authentication tag.",
    );
  }

  if (body.length !== binding.ciphertextBytes) {
    throw new ApiError(
      400,
      "INVALID_UPLOAD_LENGTH",
      "The encrypted original must be exactly 16 bytes longer than the plaintext size.",
    );
  }

  if (sha256Hex(body) !== binding.ciphertextSha256) {
    throw new ApiError(
      400,
      "CIPHERTEXT_DIGEST_MISMATCH",
      "The uploaded ciphertext does not match its declared SHA-256 digest.",
    );
  }

  return {
    ...binding,
    body,
  };
}

export function resolveS3Config(environment = process.env) {
  const values = Object.fromEntries(
    S3_CONFIG_KEYS.map((key) => [key, String(environment[key] ?? "").trim()]),
  );
  const present = S3_CONFIG_KEYS.filter((key) => values[key]);
  if (present.length === 0) {
    if (String(environment.DATABASE_MODE ?? "").toLowerCase() === "required") {
      throw new Error(
        "Private S3 storage is required in DATABASE_MODE=required, but the five S3 variables are not configured.",
      );
    }
    return null;
  }

  const missing = S3_CONFIG_KEYS.filter((key) => !values[key]);
  if (missing.length > 0) {
    throw new Error(`Incomplete S3 configuration. Missing: ${missing.join(", ")}.`);
  }

  let endpoint;
  try {
    endpoint = new URL(values.S3_ENDPOINT);
  } catch {
    throw new Error("S3_ENDPOINT must be a valid URL.");
  }
  if (endpoint.protocol !== "https:" && endpoint.protocol !== "http:") {
    throw new Error("S3_ENDPOINT must use http:// or https://.");
  }

  return {
    accessKeyId: values.S3_ACCESS_KEY,
    bucket: values.S3_BUCKET,
    endpoint: endpoint.toString().replace(/\/$/, ""),
    region: values.S3_REGION,
    secretAccessKey: values.S3_SECRET_KEY,
    forcePathStyle: ["localhost", "127.0.0.1", "::1"].includes(endpoint.hostname),
  };
}

export function createS3Client(config) {
  return new S3Client({
    endpoint: config.endpoint,
    region: config.region,
    forcePathStyle: config.forcePathStyle,
    credentials: {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
    },
  });
}

async function bodyToBuffer(body) {
  if (!body) throw new Error("The stored encrypted original has an empty response body.");
  if (typeof body.transformToByteArray === "function") {
    return Buffer.from(await body.transformToByteArray());
  }
  const chunks = [];
  for await (const chunk of body) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

export function createS3ObjectStore({ client, bucket }) {
  async function headDescriptorAtKey(objectKey, descriptor, input) {
    let head;
    try {
      head = await client.send(
        new HeadObjectCommand({ Bucket: bucket, Key: objectKey }),
      );
    } catch (error) {
      if (isNotFound(error)) {
        throw new ApiError(
          409,
          "STORAGE_OBJECT_NOT_FOUND",
          "The client-encrypted original was not found in private object storage.",
        );
      }
      throw error;
    }
    assertStoredMetadata(head, descriptor, input);
    return head;
  }

  async function findDescriptorAtKey(objectKey, descriptor, input) {
    try {
      const head = await client.send(
        new HeadObjectCommand({ Bucket: bucket, Key: objectKey }),
      );
      assertStoredMetadata(head, descriptor, input);
      return head;
    } catch (error) {
      if (isNotFound(error)) return null;
      throw error;
    }
  }

  function copySource(objectKey) {
    const encodedBucket = encodeURIComponent(bucket);
    const encodedKey = objectKey
      .split("/")
      .map((segment) => encodeURIComponent(segment))
      .join("/");
    return `${encodedBucket}/${encodedKey}`;
  }

  return {
    mode: "s3",
    persistent: true,

    async putStagedEncryptedOriginal(upload) {
      const descriptor = descriptorFromUpload(upload);
      validateEncryptedObjectDescriptor(descriptor, upload.submissionId);
      const stagedObjectKey = stagingObjectKey(upload);

      if (
        await findDescriptorAtKey(descriptor.objectKey, descriptor, upload)
      ) {
        return { descriptor, created: false, staged: false };
      }
      if (await findDescriptorAtKey(stagedObjectKey, descriptor, upload)) {
        return { descriptor, created: false, staged: true };
      }

      await client.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: stagedObjectKey,
          Body: upload.body,
          ContentLength: upload.body.length,
          ContentType: "application/vnd.sitesealed.encrypted-original",
          CacheControl: "private, no-store",
          Metadata: storageMetadata(upload),
          Tagging: "sitesealed-state=staging",
        }),
      );
      return { descriptor, created: true, staged: true };
    },

    async promoteEncryptedOriginal(descriptor, input) {
      const validated = validateEncryptedObjectDescriptor(
        descriptor,
        input.submissionId,
      );
      if (
        await findDescriptorAtKey(
          validated.objectKey,
          validated,
          input,
        )
      ) {
        return { descriptor: validated, created: false };
      }

      const stagedObjectKey = stagingObjectKey({
        submissionId: input.submissionId,
        ciphertextSha256: validated.ciphertextSha256,
      });
      await headDescriptorAtKey(stagedObjectKey, validated, input);
      await client.send(
        new CopyObjectCommand({
          Bucket: bucket,
          Key: validated.objectKey,
          CopySource: copySource(stagedObjectKey),
          MetadataDirective: "COPY",
          TaggingDirective: "REPLACE",
          Tagging: "sitesealed-state=sealed",
        }),
      );
      await headDescriptorAtKey(validated.objectKey, validated, input);
      return { descriptor: validated, created: true };
    },

    async discardStagedEncryptedOriginal(descriptor, input) {
      const validated = validateEncryptedObjectDescriptor(
        descriptor,
        input.submissionId,
      );
      const key = stagingObjectKey({
        submissionId: input.submissionId,
        ciphertextSha256: validated.ciphertextSha256,
      });
      await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
    },

    async cleanupStagedObjects({ olderThan, limit = 1000 } = {}) {
      const cutoff = new Date(olderThan ?? Date.now() - 24 * 60 * 60 * 1000);
      if (!Number.isFinite(cutoff.valueOf())) {
        throw new Error("The staging cleanup cutoff must be a valid date.");
      }
      const maximum = Math.max(1, Math.min(Number(limit) || 1000, 10000));
      let continuationToken;
      let scanned = 0;
      let deleted = 0;
      let deletedBytes = 0;
      let truncated = false;

      do {
        const page = await client.send(
          new ListObjectsV2Command({
            Bucket: bucket,
            Prefix: STAGING_PREFIX,
            ContinuationToken: continuationToken,
            MaxKeys: Math.min(1000, maximum - scanned),
          }),
        );
        const contents = Array.isArray(page.Contents) ? page.Contents : [];
        for (const object of contents) {
          if (scanned >= maximum) break;
          scanned += 1;
          const key = String(object.Key ?? "");
          const lastModified = new Date(object.LastModified ?? 0);
          if (
            !key.startsWith(STAGING_PREFIX) ||
            !Number.isFinite(lastModified.valueOf()) ||
            lastModified > cutoff
          ) {
            continue;
          }
          await client.send(
            new DeleteObjectCommand({ Bucket: bucket, Key: key }),
          );
          deleted += 1;
          deletedBytes += Math.max(0, Number(object.Size) || 0);
        }
        continuationToken = page.IsTruncated
          ? page.NextContinuationToken
          : undefined;
        truncated = Boolean(continuationToken);
      } while (continuationToken && scanned < maximum);

      return {
        status: "COMPLETED",
        prefix: STAGING_PREFIX,
        cutoff: cutoff.toISOString(),
        scanned,
        deleted,
        deletedBytes,
        truncated: truncated && scanned >= maximum,
      };
    },

    async getEncryptedOriginal(reference) {
      const result = await client.send(
        new GetObjectCommand({ Bucket: bucket, Key: reference.objectKey }),
      );
      const body = await bodyToBuffer(result.Body);
      if (
        body.length !== reference.ciphertextBytes ||
        sha256Hex(body) !== reference.ciphertextSha256
      ) {
        throw new Error("Stored encrypted original integrity check failed.");
      }
      return body;
    },

    async healthCheck() {
      await client.send(new HeadBucketCommand({ Bucket: bucket }));
      return {
        mode: "s3",
        status: "connected",
        persistent: true,
        writable: true,
        private: true,
        clientEncryptedOnly: true,
        stagedUploadPrefix: STAGING_PREFIX,
        orphanCleanup: "APPLICATION_WORKER",
      };
    },

    async assertWritable() {
      const key = `.sitesealed-health/${randomUUID()}`;
      try {
        await client.send(
          new PutObjectCommand({
            Bucket: bucket,
            Key: key,
            Body: Buffer.alloc(0),
            ContentLength: 0,
            ContentType: "application/octet-stream",
            Metadata: { purpose: "startup-write-probe" },
          }),
        );
      } finally {
        await client
          .send(new DeleteObjectCommand({ Bucket: bucket, Key: key }))
          .catch(() => {});
      }
    },

    async close() {
      client.destroy?.();
    },
  };
}

export function createMemoryObjectStore({ now = () => Date.now() } = {}) {
  const objects = new Map();

  return {
    mode: "memory",
    persistent: false,

    async putStagedEncryptedOriginal(upload) {
      const descriptor = descriptorFromUpload(upload);
      validateEncryptedObjectDescriptor(descriptor, upload.submissionId);
      const stagedObjectKey = stagingObjectKey(upload);
      const final = objects.get(descriptor.objectKey);
      if (final) {
        assertStoredMetadata(
          { ContentLength: final.body.length, Metadata: final.metadata },
          descriptor,
          upload,
        );
        return { descriptor, created: false, staged: false };
      }
      const existing = objects.get(stagedObjectKey);
      if (existing) {
        assertStoredMetadata(
          {
            ContentLength: existing.body.length,
            Metadata: existing.metadata,
          },
          descriptor,
          upload,
        );
        return { descriptor, created: false, staged: true };
      }
      objects.set(stagedObjectKey, {
        body: Buffer.from(upload.body),
        metadata: storageMetadata(upload),
        createdAt: now(),
      });
      return { descriptor, created: true, staged: true };
    },

    async promoteEncryptedOriginal(descriptor, input) {
      const validated = validateEncryptedObjectDescriptor(
        descriptor,
        input.submissionId,
      );
      const final = objects.get(validated.objectKey);
      if (final) {
        assertStoredMetadata(
          { ContentLength: final.body.length, Metadata: final.metadata },
          validated,
          input,
        );
        return { descriptor: validated, created: false };
      }
      const stagedObjectKey = stagingObjectKey({
        submissionId: input.submissionId,
        ciphertextSha256: validated.ciphertextSha256,
      });
      const staged = objects.get(stagedObjectKey);
      if (!staged) {
        throw new ApiError(
          409,
          "STORAGE_OBJECT_NOT_FOUND",
          "The client-encrypted original was not found in local object storage.",
        );
      }
      assertStoredMetadata(
        { ContentLength: staged.body.length, Metadata: staged.metadata },
        validated,
        input,
      );
      objects.set(validated.objectKey, {
        body: Buffer.from(staged.body),
        metadata: { ...staged.metadata },
        createdAt: now(),
      });
      return { descriptor: validated, created: true };
    },

    async discardStagedEncryptedOriginal(descriptor, input) {
      const validated = validateEncryptedObjectDescriptor(
        descriptor,
        input.submissionId,
      );
      objects.delete(
        stagingObjectKey({
          submissionId: input.submissionId,
          ciphertextSha256: validated.ciphertextSha256,
        }),
      );
    },

    async cleanupStagedObjects({ olderThan, limit = 1000 } = {}) {
      const cutoff = new Date(olderThan ?? Date.now() - 24 * 60 * 60 * 1000);
      const maximum = Math.max(1, Math.min(Number(limit) || 1000, 10000));
      let scanned = 0;
      let deleted = 0;
      let deletedBytes = 0;
      for (const [key, object] of objects) {
        if (!key.startsWith(STAGING_PREFIX) || scanned >= maximum) continue;
        scanned += 1;
        if (object.createdAt > cutoff.valueOf()) continue;
        objects.delete(key);
        deleted += 1;
        deletedBytes += object.body.length;
      }
      return {
        status: "COMPLETED",
        prefix: STAGING_PREFIX,
        cutoff: cutoff.toISOString(),
        scanned,
        deleted,
        deletedBytes,
        truncated:
          [...objects.keys()].filter((key) => key.startsWith(STAGING_PREFIX))
            .length > scanned,
      };
    },

    async getEncryptedOriginal(reference) {
      const stored = objects.get(reference.objectKey);
      if (!stored) throw new Error("Stored encrypted original not found.");
      const body = Buffer.from(stored.body);
      if (sha256Hex(body) !== reference.ciphertextSha256) {
        throw new Error("Stored encrypted original integrity check failed.");
      }
      return body;
    },

    async healthCheck() {
      return {
        mode: "memory",
        status: "not_configured",
        persistent: false,
        writable: true,
        private: true,
        clientEncryptedOnly: true,
        stagedUploadPrefix: STAGING_PREFIX,
        orphanCleanup: "APPLICATION_WORKER",
      };
    },

    async assertWritable() {},
    async close() {},
  };
}

export async function createS3ObjectStoreFromEnv(environment = process.env) {
  const config = resolveS3Config(environment);
  if (!config) return null;

  const client = createS3Client(config);
  const store = createS3ObjectStore({ client, bucket: config.bucket });
  try {
    await store.healthCheck();
    await store.assertWritable();
    return store;
  } catch (error) {
    await store.close();
    throw error;
  }
}
