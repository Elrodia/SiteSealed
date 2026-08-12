import { createHash, randomUUID } from "node:crypto";

export const RECORD_CLASS_IMPORTED = "IMPORTED_FILE";
export const PROOF_LEVEL_DEVELOPMENT = "DEVELOPMENT_RECEIPT";
export const SEAL_PROTOCOL_VERSION = "1.2";
export const MAX_ENCRYPTED_MANIFEST_BYTES = 64 * 1024;
export const MAX_ORIGINAL_BYTES = 25 * 1024 * 1024;
export const MAX_ENCRYPTED_ORIGINAL_BYTES = MAX_ORIGINAL_BYTES + 16;

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RECORD_ID_PATTERN = /^SR-[A-Z0-9-]{8,60}$/;
const TOP_LEVEL_FIELDS = new Set([
  "submissionId",
  "protocolVersion",
  "recordClass",
  "recordSha256",
  "manifestSha256",
  "encryptedManifest",
  "encryptedObject",
]);
const ENVELOPE_FIELDS = new Set([
  "version",
  "algorithm",
  "iv",
  "ciphertext",
]);
const ENCRYPTED_OBJECT_FIELDS = new Set([
  "version",
  "storageClass",
  "objectKey",
  "algorithm",
  "iv",
  "ciphertextSha256",
  "ciphertextBytes",
  "plaintextBytes",
  "recoveryTokenSha256",
]);

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

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

export function stableStringify(value) {
  return JSON.stringify(sortJsonValue(value));
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function normalizeRecordId(value) {
  return String(value ?? "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "");
}

export function isValidRecordId(value) {
  return RECORD_ID_PATTERN.test(normalizeRecordId(value));
}

function assertObject(value, code, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiError(400, code, message);
  }
}

function rejectUnknownFields(object, allowed, label) {
  const unknown = Object.keys(object).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw new ApiError(
      400,
      "UNEXPECTED_FIELD",
      `${label} contains unsupported field${unknown.length > 1 ? "s" : ""}: ${unknown.join(", ")}. Original file bytes must never be sent to this endpoint.`,
    );
  }
}

export function normalizeDigest(value, fieldName) {
  const digest = String(value ?? "").trim().toLowerCase();
  if (!SHA256_PATTERN.test(digest)) {
    throw new ApiError(
      400,
      "INVALID_SHA256",
      `${fieldName} must be a 64-character hexadecimal SHA-256 digest.`,
    );
  }
  return digest;
}

export function decodeCanonicalBase64(value, fieldName) {
  const encoded = String(value ?? "").trim();
  if (
    encoded.length === 0 ||
    encoded.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)
  ) {
    throw new ApiError(400, "INVALID_ENCRYPTED_MANIFEST", `${fieldName} must be canonical base64.`);
  }

  const decoded = Buffer.from(encoded, "base64");
  if (decoded.toString("base64") !== encoded) {
    throw new ApiError(400, "INVALID_ENCRYPTED_MANIFEST", `${fieldName} must be canonical base64.`);
  }
  return decoded;
}

export function normalizeSubmissionId(value) {
  const submissionId = String(value ?? "").trim().toLowerCase();
  if (!UUID_PATTERN.test(submissionId)) {
    throw new ApiError(400, "INVALID_SUBMISSION_ID", "submissionId must be a random UUID v4.");
  }
  return submissionId;
}

function positiveByteCount(value, fieldName, maximum) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new ApiError(
      400,
      "INVALID_ENCRYPTED_OBJECT",
      `${fieldName} must be a positive integer no greater than ${maximum}.`,
    );
  }
  return value;
}

export function validateEncryptedObjectDescriptor(value, submissionId) {
  assertObject(
    value,
    "INVALID_ENCRYPTED_OBJECT",
    "encryptedObject must describe the client-encrypted original stored privately.",
  );
  rejectUnknownFields(value, ENCRYPTED_OBJECT_FIELDS, "encryptedObject");

  if (
    value.version !== 1 ||
    value.storageClass !== "PRIVATE_CLIENT_ENCRYPTED_ORIGINAL" ||
    value.algorithm !== "AES-256-GCM"
  ) {
    throw new ApiError(
      400,
      "INVALID_ENCRYPTED_OBJECT",
      "encryptedObject must use the private AES-256-GCM v1 storage envelope.",
    );
  }

  const ciphertextSha256 = normalizeDigest(
    value.ciphertextSha256,
    "encryptedObject.ciphertextSha256",
  );
  const recoveryTokenSha256 = normalizeDigest(
    value.recoveryTokenSha256,
    "encryptedObject.recoveryTokenSha256",
  );
  const iv = decodeCanonicalBase64(value.iv, "encryptedObject.iv");
  if (iv.length !== 12) {
    throw new ApiError(
      400,
      "INVALID_ENCRYPTED_OBJECT",
      "The encrypted original AES-GCM initialisation vector must contain exactly 12 bytes.",
    );
  }

  const plaintextBytes = positiveByteCount(
    value.plaintextBytes,
    "encryptedObject.plaintextBytes",
    MAX_ORIGINAL_BYTES,
  );
  const ciphertextBytes = positiveByteCount(
    value.ciphertextBytes,
    "encryptedObject.ciphertextBytes",
    MAX_ENCRYPTED_ORIGINAL_BYTES,
  );
  if (ciphertextBytes !== plaintextBytes + 16) {
    throw new ApiError(
      400,
      "INVALID_ENCRYPTED_OBJECT",
      "The AES-GCM ciphertext must be exactly 16 bytes longer than the original.",
    );
  }

  const expectedObjectKey =
    `sealed/v1.2/${submissionId}/${ciphertextSha256.slice(0, 2)}/` +
    `${ciphertextSha256}.ssenc`;
  if (value.objectKey !== expectedObjectKey) {
    throw new ApiError(
      400,
      "INVALID_ENCRYPTED_OBJECT",
      "encryptedObject.objectKey does not match its submission and ciphertext digest.",
    );
  }

  return {
    version: 1,
    storageClass: "PRIVATE_CLIENT_ENCRYPTED_ORIGINAL",
    objectKey: expectedObjectKey,
    algorithm: "AES-256-GCM",
    iv: value.iv,
    ciphertextSha256,
    ciphertextBytes,
    plaintextBytes,
    recoveryTokenSha256,
  };
}

export function validateSealRequest(body) {
  assertObject(body, "INVALID_SEAL_REQUEST", "The sealing request must be a JSON object.");
  rejectUnknownFields(body, TOP_LEVEL_FIELDS, "The sealing request");

  const submissionId = normalizeSubmissionId(body.submissionId);

  if (body.protocolVersion !== SEAL_PROTOCOL_VERSION) {
    throw new ApiError(
      400,
      "UNSUPPORTED_PROTOCOL",
      `protocolVersion must be ${SEAL_PROTOCOL_VERSION}.`,
    );
  }

  if (body.recordClass !== RECORD_CLASS_IMPORTED) {
    throw new ApiError(
      400,
      "INVALID_RECORD_CLASS",
      "The v1.3 web workflow accepts only explicitly labelled imported files.",
    );
  }

  assertObject(
    body.encryptedManifest,
    "INVALID_ENCRYPTED_MANIFEST",
    "encryptedManifest must be an AES-GCM envelope.",
  );
  rejectUnknownFields(body.encryptedManifest, ENVELOPE_FIELDS, "encryptedManifest");

  if (
    body.encryptedManifest.version !== 1 ||
    body.encryptedManifest.algorithm !== "AES-256-GCM"
  ) {
    throw new ApiError(
      400,
      "INVALID_ENCRYPTED_MANIFEST",
      "encryptedManifest must use the AES-256-GCM v1 envelope.",
    );
  }

  const iv = decodeCanonicalBase64(body.encryptedManifest.iv, "encryptedManifest.iv");
  const ciphertext = decodeCanonicalBase64(
    body.encryptedManifest.ciphertext,
    "encryptedManifest.ciphertext",
  );
  if (iv.length !== 12) {
    throw new ApiError(
      400,
      "INVALID_ENCRYPTED_MANIFEST",
      "The AES-GCM initialisation vector must contain exactly 12 bytes.",
    );
  }
  if (ciphertext.length < 17 || ciphertext.length > MAX_ENCRYPTED_MANIFEST_BYTES) {
    throw new ApiError(
      400,
      "INVALID_ENCRYPTED_MANIFEST",
      `The encrypted manifest must contain between 17 and ${MAX_ENCRYPTED_MANIFEST_BYTES} bytes.`,
    );
  }

  return {
    submissionId,
    protocolVersion: SEAL_PROTOCOL_VERSION,
    recordClass: RECORD_CLASS_IMPORTED,
    recordSha256: normalizeDigest(body.recordSha256, "recordSha256"),
    manifestSha256: normalizeDigest(body.manifestSha256, "manifestSha256"),
    encryptedManifest: {
      version: 1,
      algorithm: "AES-256-GCM",
      iv: body.encryptedManifest.iv,
      ciphertext: body.encryptedManifest.ciphertext,
    },
    encryptedObject: validateEncryptedObjectDescriptor(
      body.encryptedObject,
      submissionId,
    ),
  };
}

export function serializeEncryptedManifest(envelope) {
  return Buffer.from(stableStringify(envelope), "utf8");
}

export function parseEncryptedManifest(value) {
  if (!value) return null;
  const text = Buffer.isBuffer(value) ? value.toString("utf8") : String(value);
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

export function createRecordId(receivedAt = new Date()) {
  const date = receivedAt.toISOString().slice(0, 10).replaceAll("-", "");
  const randomPart = randomUUID().replaceAll("-", "").slice(0, 24).toUpperCase();
  return `SR-${date}-${randomPart}`;
}

export function createReceiptPayload({
  recordId,
  recordClass,
  recordSha256,
  manifestSha256,
  encryptedObject,
  receivedAt,
}) {
  const receipt = {
    schemaVersion: encryptedObject
      ? "sitesealed.receipt.v1.2"
      : "sitesealed.receipt.v1",
    recordId,
    recordClass,
    proofLevel: PROOF_LEVEL_DEVELOPMENT,
    recordSha256,
    manifestSha256,
    receivedAt,
  };
  if (encryptedObject) {
    receipt.encryptedOriginal = {
      state: "STORED_ENCRYPTED",
      algorithm: encryptedObject.algorithm,
      iv: encryptedObject.iv,
      ciphertextSha256: encryptedObject.ciphertextSha256,
      ciphertextBytes: encryptedObject.ciphertextBytes,
      plaintextBytes: encryptedObject.plaintextBytes,
    };
  }
  return receipt;
}

export function createDevelopmentRecord(input, options = {}) {
  const receivedAt = (options.receivedAt ?? new Date()).toISOString();
  const recordId = options.recordId ?? createRecordId(new Date(receivedAt));
  const receipt = createReceiptPayload({
    recordId,
    recordClass: input.recordClass,
    recordSha256: input.recordSha256,
    manifestSha256: input.manifestSha256,
    encryptedObject: input.encryptedObject,
    receivedAt,
  });

  const encryptedObject = input.encryptedObject ?? null;

  return {
    recordId,
    specimen: false,
    recordClass: input.recordClass,
    proofLevel: PROOF_LEVEL_DEVELOPMENT,
    classification: "Imported file - web sealing workflow",
    project: "Encrypted in the client-held manifest",
    description:
      "The readable manifest and plaintext original remain under client control.",
    file: encryptedObject
      ? "Client-encrypted original stored in private object storage"
      : "Original retained by the client",
    captureMode: "Browser import - not a live in-app capture",
    capturedAt: null,
    qualifiedAt: null,
    receivedAt,
    position: "Not collected in the v1.3 web import workflow",
    sha256: input.recordSha256,
    manifestSha256: input.manifestSha256,
    manifestEncryption: "AES-256-GCM / client-held key",
    storage: encryptedObject
      ? {
          state: "STORED_ENCRYPTED",
          provider: options.storageProvider ?? "PRIVATE_OBJECT_STORAGE",
          encryption: "AES-256-GCM / client-held key",
          ciphertextSha256: encryptedObject.ciphertextSha256,
          ciphertextBytes: encryptedObject.ciphertextBytes,
          plaintextBytes: encryptedObject.plaintextBytes,
          privateRetrieval: true,
        }
      : {
          state: "NOT_STORED_LEGACY",
          provider: null,
          encryption: null,
          ciphertextSha256: null,
          ciphertextBytes: null,
          plaintextBytes: null,
          privateRetrieval: false,
        },
    receipt,
    receiptSha256: sha256Hex(stableStringify(receipt)),
    qualifiedRail: {
      state: "NOT_ISSUED",
      provider: "Not issued in v1.3",
      token: null,
      status: "No qualified RFC 3161 timestamp token has been issued.",
    },
    chainRail: {
      state: "NOT_ANCHORED",
      chain: "Not anchored in v1.3",
      block: null,
      anchor: null,
      merkleRoot: null,
      batchSize: null,
      status: "No public-chain Merkle anchor has been created.",
    },
  };
}

export function scopeForRecord(record) {
  if (record.specimen) {
    return {
      proves: "The interface and persistence path can return the simulated specimen bundle.",
      attests: "All capture, identity, location, QTSP and blockchain data are simulated.",
      doesNotProve:
        "The specimen is not a certified document and does not prove that the depicted scene existed or was unstaged.",
    };
  }

  const encryptedStorageStatement =
    record.storage?.state === "STORED_ENCRYPTED"
      ? " SiteSealed also stored a client-encrypted ciphertext bound to the receipt by its own SHA-256 digest."
      : " No encrypted original is attached to this legacy development receipt.";

  return {
    proves:
      "If a locally held file recalculates to the recorded SHA-256 digest, its byte sequence matches this receipt." +
      encryptedStorageStatement,
    attests:
      "The displayed receipt time is a SiteSealed server database time. The v1.3 PostgreSQL hash chain is an internal operational audit trail, not an independent timestamp.",
    doesNotProve:
      "Without the client-held key, SiteSealed cannot inspect the stored plaintext or prove that the ciphertext decrypts to the claimed file. MySQL, PostgreSQL and Redis do not replace either external trust rail. This receipt also does not prove capture time, identity, authorship, location, truthfulness, a qualified eIDAS timestamp or a public blockchain anchor.",
  };
}

export function createProofBundle(record, encryptedManifest = null) {
  return {
    schemaVersion: "sitesealed.proof-bundle.v1.2",
    bundleVersion: "1.2",
    generatedAt: new Date().toISOString(),
    record: {
      recordId: record.recordId,
      recordClass: record.recordClass,
      proofLevel: record.proofLevel,
      recordSha256: record.sha256,
      manifestSha256: record.manifestSha256,
      receivedAt: record.receivedAt,
    },
    receipt: record.receipt,
    receiptSha256: record.receiptSha256,
    encryptedManifest,
    encryptedOriginal: record.storage,
    proofs: {
      qualifiedTimestamp: {
        state: record.qualifiedRail.state,
        provider: record.qualifiedRail.provider,
        token: record.qualifiedRail.token,
      },
      publicChain: {
        state: record.chainRail.state,
        chain: record.chainRail.chain,
        transaction: record.chainRail.anchor,
        merkleRoot: record.chainRail.merkleRoot,
      },
    },
    scope: scopeForRecord(record),
  };
}
