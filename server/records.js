import { createHash, randomUUID } from "node:crypto";

export const RECORD_CLASS_IMPORTED = "IMPORTED_FILE";
export const PROOF_LEVEL_DEVELOPMENT = "DEVELOPMENT_RECEIPT";
export const PROOF_LEVEL_DUAL_RAIL_ALPHA = "DUAL_RAIL_ALPHA_RECEIPT";
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

export function createEvidenceDigest({ recordSha256, manifestSha256 }) {
  const recordDigest = normalizeDigest(recordSha256, "recordSha256");
  const manifestDigest = normalizeDigest(manifestSha256, "manifestSha256");
  return sha256Hex(
    Buffer.concat([
      Buffer.from("SiteSealed evidence digest v1\0", "utf8"),
      Buffer.from(recordDigest, "hex"),
      Buffer.from(manifestDigest, "hex"),
    ]),
  );
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
      "The v1.4 alpha web workflow accepts only explicitly labelled imported files.",
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
  receiptVersion = "1.4-alpha.1",
  proofLevel = PROOF_LEVEL_DUAL_RAIL_ALPHA,
}) {
  const evidenceDigest = createEvidenceDigest({
    recordSha256,
    manifestSha256,
  });
  const alphaReceipt = receiptVersion === "1.4-alpha.1";
  const receipt = {
    schemaVersion: alphaReceipt
      ? "sitesealed.receipt.v1.4-alpha.1"
      : encryptedObject
        ? "sitesealed.receipt.v1.2"
        : "sitesealed.receipt.v1",
    recordId,
    recordClass,
    proofLevel: alphaReceipt ? proofLevel : PROOF_LEVEL_DEVELOPMENT,
    recordSha256,
    manifestSha256,
    receivedAt,
  };
  if (alphaReceipt) receipt.evidenceDigest = evidenceDigest;
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
  const receiptVersion = options.receiptVersion ?? "1.4-alpha.1";
  const proofLevel =
    options.proofLevel ??
    (receiptVersion === "1.4-alpha.1"
      ? PROOF_LEVEL_DUAL_RAIL_ALPHA
      : PROOF_LEVEL_DEVELOPMENT);
  const receipt = createReceiptPayload({
    recordId,
    recordClass: input.recordClass,
    recordSha256: input.recordSha256,
    manifestSha256: input.manifestSha256,
    encryptedObject: input.encryptedObject,
    receivedAt,
    receiptVersion,
    proofLevel,
  });

  const encryptedObject = input.encryptedObject ?? null;

  return {
    recordId,
    specimen: false,
    recordClass: input.recordClass,
    proofLevel,
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
    position: "Not collected in the v1.4 web import workflow",
    sha256: input.recordSha256,
    manifestSha256: input.manifestSha256,
    evidenceDigest: createEvidenceDigest({
      recordSha256: input.recordSha256,
      manifestSha256: input.manifestSha256,
    }),
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
      provider: "Evidency sandbox",
      token: null,
      environment: "SANDBOX",
      legalUse: false,
      qualificationStatus: "NOT_ISSUED",
      signatureVerification: "NOT_AVAILABLE",
      status: "No Evidency sandbox RFC 3161 token has been issued.",
    },
    chainRail: {
      state: "NOT_ANCHORED",
      chain: "Ethereum mainnet",
      chainId: 1,
      block: null,
      anchor: null,
      merkleRoot: null,
      batchSize: null,
      inclusionPath: null,
      confirmations: 0,
      finalityStatus: "NOT_ANCHORED",
      status: "No Ethereum mainnet Merkle anchor has been created.",
    },
  };
}

export function externalProofStatus(record) {
  if (record?.specimen) {
    return {
      state: "SPECIMEN",
      proofsComplete: false,
      alphaComplete: false,
      sealed: false,
    };
  }
  const qualified =
    record?.qualifiedRail?.qualificationStatus === "EIDAS_QUALIFIED" &&
    record?.qualifiedRail?.signatureVerification === "VALID";
  const sandbox =
    record?.qualifiedRail?.state === "SANDBOX_TOKEN_ISSUED" &&
    record?.qualifiedRail?.signatureVerification === "VALID" &&
    record?.qualifiedRail?.certificateChainVerification ===
      "VALID_TO_PINNED_SANDBOX_ROOT";
  const finalized = record?.chainRail?.state === "FINALIZED";
  const anchorRejected = ["FAILED_ON_CHAIN", "INVALID_ON_CHAIN"].includes(
    record?.chainRail?.state,
  );
  return {
    state:
      anchorRejected
        ? "PUBLIC_ANCHOR_REJECTED"
        : qualified && finalized
        ? "DUAL_RAIL_COMPLETE"
        : sandbox && finalized
          ? "ALPHA_DUAL_RAIL_COMPLETE"
          : sandbox
            ? "SANDBOX_TIMESTAMP_ISSUED_ANCHOR_PENDING"
            : finalized
              ? "MAINNET_ANCHORED_QTSP_PENDING"
              : "EXTERNAL_PROOFS_PENDING",
    proofsComplete: Boolean(qualified && finalized),
    alphaComplete: Boolean(sandbox && finalized),
    sealed: Boolean(qualified && finalized),
  };
}

export function qualifiedRailFromProof(proof) {
  if (!proof) return null;
  const sandbox = String(proof.environment ?? "").toUpperCase() === "SANDBOX";
  const independentlyVerified =
    proof.signatureVerification === "VALID" &&
    proof.certificateChainVerification ===
      "VALID_TO_PINNED_SANDBOX_ROOT";
  return {
    state: sandbox ? "SANDBOX_TOKEN_ISSUED" : "TOKEN_ISSUED",
    provider: proof.provider ?? "Evidency",
    environment: sandbox ? "SANDBOX" : "PRODUCTION",
    legalUse: Boolean(proof.legalUse) && !sandbox,
    qualificationStatus:
      proof.qualificationStatus ??
      (sandbox ? "TEST_ONLY_NOT_QUALIFIED" : "UNDETERMINED"),
    hashAlgorithm: proof.hashAlgorithm ?? "SHA256",
    hashedMessage: proof.hashedMessage ?? null,
    serialNumber: proof.serialNumber ?? null,
    certifiedAt: proof.certifiedAt ?? null,
    token: proof.tokenBase64 ?? null,
    tokenSha256: proof.tokenSha256 ?? null,
    tsaPolicyId: proof.tsaPolicyId ?? null,
    providerStatus: proof.providerStatus ?? null,
    responseValidation: proof.responseValidation ?? null,
    signatureVerification:
      proof.signatureVerification ?? "NOT_INDEPENDENTLY_VERIFIED",
    validatorVersion: proof.validatorVersion ?? null,
    certificateChainVerification:
      proof.certificateChainVerification ?? "NOT_INDEPENDENTLY_VERIFIED",
    signingCertificateVerification:
      proof.signingCertificateVerification ?? "NOT_INDEPENDENTLY_VERIFIED",
    signingCertificateHashAlgorithm:
      proof.signingCertificateHashAlgorithm ?? null,
    cmsAlgorithmProtection: proof.cmsAlgorithmProtection ?? null,
    revocationVerification: proof.revocationVerification ?? "NOT_CHECKED",
    cmsDigestAlgorithm: proof.cmsDigestAlgorithm ?? null,
    cmsSignatureAlgorithm: proof.cmsSignatureAlgorithm ?? null,
    signerCertificateSha256: proof.signerCertificateSha256 ?? null,
    trustAnchorSha256: proof.trustAnchorSha256 ?? null,
    certificatePathLength:
      proof.certificatePathLength === null ||
      proof.certificatePathLength === undefined
        ? null
        : Number(proof.certificatePathLength),
    status: sandbox
      ? independentlyVerified
        ? "Evidency sandbox token issued; CMS signature, ESSCertIDv2 and certificate path to the pinned sandbox root verified independently. Test-only, without qualified legal effect; revocation not checked."
        : "Evidency sandbox token issued but not independently verified by this release. Test-only, without qualified legal effect."
      : "Timestamp token issued; qualification must be independently validated.",
  };
}

export function chainRailFromProof(proof) {
  if (!proof) return null;
  const state = String(proof.state ?? "SUBMITTED").toUpperCase();
  return {
    state,
    chain: proof.chain ?? "Ethereum mainnet",
    chainId: Number(proof.chainId ?? 1),
    block:
      proof.blockNumber === null || proof.blockNumber === undefined
        ? null
        : Number(proof.blockNumber).toLocaleString("en-US"),
    blockNumber:
      proof.blockNumber === null || proof.blockNumber === undefined
        ? null
        : Number(proof.blockNumber),
    blockHash: proof.blockHash ?? null,
    anchor: proof.transactionHash ?? null,
    transactionInput: proof.transactionInput ?? null,
    anchorAddress: proof.anchorAddress ?? null,
    merkleProtocol: proof.merkleProtocol ?? "SITESEALED_MERKLE_SHA256_V1",
    merkleRoot: proof.merkleRoot ?? null,
    leafHash: proof.leafHash ?? null,
    leafIndex:
      proof.leafIndex === null || proof.leafIndex === undefined
        ? null
        : Number(proof.leafIndex),
    inclusionPath: proof.inclusionPath ?? null,
    batchId: proof.batchId ?? null,
    batchSize:
      proof.batchSize === null || proof.batchSize === undefined
        ? null
        : Number(proof.batchSize),
    confirmations: Number(proof.confirmations ?? 0),
    finalityStatus: state,
    anchoredAt: proof.anchoredAt ?? null,
    finalizedAt: proof.finalizedAt ?? null,
    verificationStatus: proof.verificationStatus ?? null,
    status:
      state === "FINALIZED"
        ? "Merkle inclusion bound to a finalized Ethereum mainnet transaction."
        : state === "INVALID_ON_CHAIN"
          ? "Ethereum transaction binding mismatch; this anchor was rejected."
          : state === "FAILED_ON_CHAIN"
            ? "Ethereum transaction failed on-chain; this receipt is not anchored."
        : state === "CONFIRMED"
          ? "Ethereum mainnet transaction confirmed; finality pending."
          : state === "SUBMITTED"
            ? "Ethereum mainnet transaction submitted; confirmations pending."
            : "Ethereum mainnet anchor is pending.",
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

  const timestampStatement =
    record.qualifiedRail?.state === "SANDBOX_TOKEN_ISSUED"
      ? record.qualifiedRail?.signatureVerification === "VALID" &&
        record.qualifiedRail?.certificateChainVerification ===
          "VALID_TO_PINNED_SANDBOX_ROOT"
        ? " Evidency sandbox returned an RFC 3161 test token bound to the evidence digest; SiteSealed independently verified its CMS signature, signer binding and certificate path to the pinned sandbox root. Revocation was not checked, and the sandbox expressly has no legal effect."
        : " Evidency sandbox returned an RFC 3161 test token, but this stored token has not passed the alpha.7.1 independent signature-and-chain gate. The sandbox expressly has no legal effect."
      : " No external RFC 3161 timestamp token is attached.";
  const chainStatement =
    record.chainRail?.state === "FINALIZED"
      ? " Its Merkle inclusion path resolves to a root recorded in a finalized Ethereum mainnet transaction."
      : record.chainRail?.state === "CONFIRMED" ||
          record.chainRail?.state === "SUBMITTED"
        ? " An Ethereum mainnet anchor exists but has not reached SiteSealed's finality state."
        : " No Ethereum mainnet anchor is attached.";

  return {
    proves:
      "If a locally held file recalculates to the recorded SHA-256 digest, its byte sequence matches this receipt." +
      encryptedStorageStatement +
      timestampStatement +
      chainStatement,
    attests:
      "The displayed receipt time is a SiteSealed server database time. PostgreSQL is an internal operational audit trail; only the exported Evidency token and Ethereum transaction are external proof artefacts.",
    doesNotProve:
      "Without the client-held key, SiteSealed cannot inspect the stored plaintext or prove that the ciphertext decrypts to the claimed file. This imported-file workflow does not prove live capture time, identity, authorship, location or truthfulness. An Evidency sandbox token is test-only and must never be described as a qualified eIDAS timestamp.",
  };
}

export function createProofBundle(record, encryptedManifest = null) {
  const proofStatus = externalProofStatus(record);
  return {
    schemaVersion: "sitesealed.proof-bundle.v1.4-alpha.1",
    bundleVersion: "1.4-alpha.1",
    generatedAt: new Date().toISOString(),
    record: {
      recordId: record.recordId,
      recordClass: record.recordClass,
      proofLevel: record.proofLevel,
      recordSha256: record.sha256,
      manifestSha256: record.manifestSha256,
      evidenceDigest: record.evidenceDigest,
      receivedAt: record.receivedAt,
    },
    receipt: record.receipt,
    receiptSha256: record.receiptSha256,
    encryptedManifest,
    encryptedOriginal: record.storage,
    proofs: {
      qualifiedTimestamp: {
        ...record.qualifiedRail,
        token: record.qualifiedRail.token
          ? {
              mediaType: "application/timestamp-reply",
              encoding: "base64",
              value: record.qualifiedRail.token,
              sha256: record.qualifiedRail.tokenSha256,
            }
          : null,
      },
      publicChain: {
        ...record.chainRail,
        transaction: record.chainRail.anchor,
      },
    },
    proofStatus,
    scope: scopeForRecord(record),
  };
}
