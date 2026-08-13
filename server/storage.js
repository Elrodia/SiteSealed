import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
  HeadObjectCommand,
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
  positiveByteCount,
  validateEncryptedObjectDescriptor,
} from "./records.js";

const S3_CONFIG_KEYS = [
  "S3_ACCESS_KEY",
  "S3_BUCKET",
  "S3_ENDPOINT",
  "S3_REGION",
  "S3_SECRET_KEY",
];
const UPLOAD_GRANT_FIELDS = new Set([
  "submissionId",
  "ciphertextSha256",
  "byteLength",
]);
export const UPLOAD_GRANT_HEADER = "x-sitesealed-upload-grant";

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

function descriptorFromUpload(upload) {
  const objectKey =
    `sealed/v1.2/${upload.submissionId}/${upload.ciphertextSha256.slice(0, 2)}/` +
    `${upload.ciphertextSha256}.ssenc`;
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

export function validateEncryptedUpload({ submissionId, headers, body }) {
  const normalizedSubmissionId = normalizeSubmissionId(submissionId);
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

  const plaintextBytes = positiveIntegerHeader(
    headers["x-sitesealed-original-bytes"],
    "x-sitesealed-original-bytes",
    MAX_ORIGINAL_BYTES,
  );
  if (body.length !== plaintextBytes + 16) {
    throw new ApiError(
      400,
      "INVALID_UPLOAD_LENGTH",
      "The encrypted original must be exactly 16 bytes longer than the plaintext size.",
    );
  }

  const ciphertextSha256 = normalizeDigest(
    headers["x-sitesealed-cipher-sha256"],
    "x-sitesealed-cipher-sha256",
  );
  if (sha256Hex(body) !== ciphertextSha256) {
    throw new ApiError(
      400,
      "CIPHERTEXT_DIGEST_MISMATCH",
      "The uploaded ciphertext does not match its declared SHA-256 digest.",
    );
  }

  const iv = String(headers["x-sitesealed-cipher-iv"] ?? "").trim();
  if (decodeCanonicalBase64(iv, "x-sitesealed-cipher-iv").length !== 12) {
    throw new ApiError(
      400,
      "INVALID_UPLOAD_METADATA",
      "x-sitesealed-cipher-iv must contain exactly 12 bytes.",
    );
  }

  return {
    submissionId: normalizedSubmissionId,
    recordSha256: normalizeDigest(
      headers["x-sitesealed-record-sha256"],
      "x-sitesealed-record-sha256",
    ),
    ciphertextSha256,
    ciphertextBytes: plaintextBytes + 16,
    plaintextBytes,
    iv,
    recoveryTokenSha256: normalizeDigest(
      headers["x-sitesealed-recovery-token-sha256"],
      "x-sitesealed-recovery-token-sha256",
    ),
    body,
  };
}

export function validateUploadGrantRequest(body) {
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    Object.keys(body).some((key) => !UPLOAD_GRANT_FIELDS.has(key))
  ) {
    throw new ApiError(
      400,
      "INVALID_UPLOAD_GRANT_REQUEST",
      "An upload grant request must contain only submissionId, ciphertextSha256 and byteLength. Original file bytes must never be sent to this endpoint.",
    );
  }

  return {
    submissionId: normalizeSubmissionId(body.submissionId),
    ciphertextSha256: normalizeDigest(body.ciphertextSha256, "ciphertextSha256"),
    byteLength: positiveByteCount(
      body.byteLength,
      "byteLength",
      MAX_ENCRYPTED_ORIGINAL_BYTES,
    ),
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
  async function headDescriptor(descriptor, input) {
    let head;
    try {
      head = await client.send(
        new HeadObjectCommand({ Bucket: bucket, Key: descriptor.objectKey }),
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

  return {
    mode: "s3",
    persistent: true,

    async putEncryptedOriginal(upload) {
      const descriptor = descriptorFromUpload(upload);
      validateEncryptedObjectDescriptor(descriptor, upload.submissionId);

      try {
        const existing = await client.send(
          new HeadObjectCommand({ Bucket: bucket, Key: descriptor.objectKey }),
        );
        assertStoredMetadata(existing, descriptor, upload);
        return { descriptor, created: false };
      } catch (error) {
        if (!isNotFound(error)) throw error;
      }

      await client.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: descriptor.objectKey,
          Body: upload.body,
          ContentLength: upload.body.length,
          ContentType: "application/vnd.sitesealed.encrypted-original",
          CacheControl: "private, no-store",
          Metadata: storageMetadata(upload),
        }),
      );
      return { descriptor, created: true };
    },

    async assertStored(descriptor, input) {
      const validated = validateEncryptedObjectDescriptor(
        descriptor,
        input.submissionId,
      );
      await headDescriptor(validated, input);
      return validated;
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

export function createMemoryObjectStore() {
  const objects = new Map();

  return {
    mode: "memory",
    persistent: false,

    async putEncryptedOriginal(upload) {
      const descriptor = descriptorFromUpload(upload);
      validateEncryptedObjectDescriptor(descriptor, upload.submissionId);
      const existing = objects.get(descriptor.objectKey);
      if (existing) {
        assertStoredMetadata(
          {
            ContentLength: existing.body.length,
            Metadata: existing.metadata,
          },
          descriptor,
          upload,
        );
        return { descriptor, created: false };
      }
      objects.set(descriptor.objectKey, {
        body: Buffer.from(upload.body),
        metadata: storageMetadata(upload),
      });
      return { descriptor, created: true };
    },

    async assertStored(descriptor, input) {
      const validated = validateEncryptedObjectDescriptor(
        descriptor,
        input.submissionId,
      );
      const stored = objects.get(validated.objectKey);
      if (!stored) {
        throw new ApiError(
          409,
          "STORAGE_OBJECT_NOT_FOUND",
          "The client-encrypted original was not found in local object storage.",
        );
      }
      assertStoredMetadata(
        { ContentLength: stored.body.length, Metadata: stored.metadata },
        validated,
        input,
      );
      return validated;
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
