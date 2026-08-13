import { gcm } from "@noble/ciphers/aes.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

export const MAX_FILE_BYTES = 25 * 1024 * 1024;
export const PROTOCOL_VERSION = "1.2";

export function createRandomUuid() {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10).join("")}`;
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

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value, label) {
  const hex = String(value ?? "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hex)) {
    throw new Error(`${label} is not a SHA-256 digest.`);
  }
  return Uint8Array.from(hex.match(/.{2}/g), (byte) => Number.parseInt(byte, 16));
}

function concatBytes(...values) {
  const length = values.reduce((sum, value) => sum + value.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function sha256Bytes(bytes) {
  if (globalThis.crypto.subtle) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
    return bytesToHex(new Uint8Array(digest));
  }
  return bytesToHex(nobleSha256(new Uint8Array(bytes)));
}

export async function recalculateEvidenceDigest(recordSha256, manifestSha256) {
  return sha256Bytes(
    concatBytes(
      new TextEncoder().encode("SiteSealed evidence digest v1\0"),
      hexToBytes(recordSha256, "recordSha256"),
      hexToBytes(manifestSha256, "manifestSha256"),
    ),
  );
}

async function merkleLeafHash(evidenceDigest) {
  return sha256Bytes(
    concatBytes(
      new Uint8Array([0]),
      hexToBytes(evidenceDigest, "evidenceDigest"),
    ),
  );
}

async function merkleParentHash(left, right) {
  return sha256Bytes(
    concatBytes(
      new Uint8Array([1]),
      hexToBytes(left, "left Merkle node"),
      hexToBytes(right, "right Merkle node"),
    ),
  );
}

export async function verifyPublicProofArtifacts(record) {
  try {
    const evidenceDigest = await recalculateEvidenceDigest(
      record?.sha256,
      record?.manifestSha256,
    );
    if (evidenceDigest !== record?.evidenceDigest) {
      return {
        state: "FAIL",
        evidenceDigest: "MISMATCH",
        merkleInclusion: "NOT_CHECKED",
        transactionBinding: "NOT_CHECKED",
      };
    }

    const rail = record?.chainRail ?? {};
    if (
      !rail.merkleRoot ||
      !Array.isArray(rail.inclusionPath) ||
      !rail.anchor
    ) {
      return {
        state: "RECEIPT_VALID_EXTERNAL_PENDING",
        evidenceDigest: "PASS",
        merkleInclusion: "NOT_ATTACHED",
        transactionBinding: "NOT_ATTACHED",
      };
    }

    let calculatedRoot = await merkleLeafHash(evidenceDigest);
    const leafMatches = !rail.leafHash || rail.leafHash === calculatedRoot;
    for (const step of rail.inclusionPath) {
      if (!step || !["left", "right"].includes(step.position)) {
        throw new Error("Invalid Merkle path step.");
      }
      calculatedRoot = step.position === "left"
        ? await merkleParentHash(step.sha256, calculatedRoot)
        : await merkleParentHash(calculatedRoot, step.sha256);
    }
    const merklePass = leafMatches && calculatedRoot === rail.merkleRoot;
    const expectedInput = `0x53534c4401${rail.merkleRoot}`;
    const currentAlpha =
      record?.receipt?.schemaVersion === "sitesealed.receipt.v1.4-alpha.1";
    const transactionBinding = rail.transactionInput
      ? Number(rail.chainId) === 1 &&
        String(rail.transactionInput).toLowerCase() === expectedInput
      : !currentAlpha;
    return {
      state: merklePass && transactionBinding ? "PASS" : "FAIL",
      evidenceDigest: "PASS",
      merkleInclusion: merklePass ? "PASS" : "MISMATCH",
      transactionBinding: rail.transactionInput
        ? transactionBinding ? "PASS" : "MISMATCH"
        : currentAlpha ? "MISSING" : "NOT_AVAILABLE_LEGACY",
    };
  } catch {
    return {
      state: "FAIL",
      evidenceDigest: "INVALID",
      merkleInclusion: "INVALID",
      transactionBinding: "INVALID",
    };
  }
}

export async function sha256File(file) {
  if (!(file instanceof Blob)) throw new TypeError("A browser File or Blob is required.");
  if (file.size <= 0) throw new Error("The selected file is empty.");
  if (file.size > MAX_FILE_BYTES) {
    throw new Error("This v1.4 alpha workflow accepts files up to 25 MB.");
  }
  return sha256Bytes(await file.arrayBuffer());
}

export function buildManifest(file, { projectReference, description }) {
  return {
    schemaVersion: "sitesealed.capture-manifest.v1",
    recordClass: "IMPORTED_FILE",
    privacy: {
      plaintextOriginalTransferred: false,
      encryptedOriginalStored: true,
      encryptionKeyTransferred: false,
    },
    file: {
      name: file.name,
      size: file.size,
      mediaType: file.type || "application/octet-stream",
      lastModifiedClientValue: new Date(file.lastModified).toISOString(),
    },
    context: {
      projectReference: projectReference.trim(),
      description: description.trim(),
    },
    client: {
      workflow: "WEB_IMPORT_V1",
      manifestCreatedAt: new Date().toISOString(),
      captureAttested: false,
      deviceAttested: false,
      locationAttested: false,
    },
  };
}

async function encryptAesGcm(plaintext, rawKey, iv) {
  if (globalThis.crypto.subtle) {
    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      rawKey,
      "AES-GCM",
      false,
      ["encrypt"],
    );
    const ciphertext = await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      plaintext,
    );
    return new Uint8Array(ciphertext);
  }
  return gcm(rawKey, iv).encrypt(plaintext);
}

export async function encryptManifest(manifest) {
  const canonicalManifest = stableStringify(manifest);
  const plaintext = new TextEncoder().encode(canonicalManifest);
  const rawKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await encryptAesGcm(plaintext, rawKey, iv);

  return {
    canonicalManifest,
    manifestSha256: await sha256Bytes(plaintext),
    envelope: {
      version: 1,
      algorithm: "AES-256-GCM",
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(ciphertext),
    },
    recoveryKey: bytesToBase64(rawKey),
  };
}

export async function encryptOriginal(file, recoveryKey) {
  if (!(file instanceof Blob)) throw new TypeError("A browser File or Blob is required.");
  if (file.size <= 0 || file.size > MAX_FILE_BYTES) {
    throw new Error("This v1.4 alpha workflow accepts files from 1 byte up to 25 MB.");
  }
  const rawKey = base64ToBytes(recoveryKey);
  if (rawKey.length !== 32) throw new Error("The sealing recovery key is invalid.");
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await encryptAesGcm(
    new Uint8Array(await file.arrayBuffer()),
    rawKey,
    iv,
  );
  return {
    ciphertext,
    envelope: {
      version: 1,
      storageClass: "PRIVATE_CLIENT_ENCRYPTED_ORIGINAL",
      algorithm: "AES-256-GCM",
      iv: bytesToBase64(iv),
      ciphertextSha256: await sha256Bytes(ciphertext),
      ciphertextBytes: ciphertext.length,
      plaintextBytes: file.size,
    },
  };
}

export async function createRecoveryToken() {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
  return {
    token: bytesToBase64(bytes),
    sha256: await sha256Bytes(bytes),
  };
}

export function createEncryptedUploadHeaders({
  recordSha256,
  encryptedOriginal,
  recoveryTokenSha256,
  uploadGrant,
}) {
  return {
    "content-type": "application/octet-stream",
    "x-sitesealed-upload-grant": uploadGrant,
    "x-sitesealed-record-sha256": recordSha256,
    "x-sitesealed-cipher-sha256": encryptedOriginal.envelope.ciphertextSha256,
    "x-sitesealed-cipher-iv": encryptedOriginal.envelope.iv,
    "x-sitesealed-original-bytes": String(
      encryptedOriginal.envelope.plaintextBytes,
    ),
    "x-sitesealed-recovery-token-sha256": recoveryTokenSha256,
  };
}

export function createUploadGrantRequest({
  submissionId,
  recordSha256,
  encryptedOriginal,
  recoveryTokenSha256,
}) {
  return {
    submissionId,
    recordSha256,
    ciphertextSha256: encryptedOriginal.envelope.ciphertextSha256,
    ciphertextBytes: encryptedOriginal.envelope.ciphertextBytes,
    plaintextBytes: encryptedOriginal.envelope.plaintextBytes,
    iv: encryptedOriginal.envelope.iv,
    recoveryTokenSha256,
  };
}

export function createSealRequest({
  recordSha256,
  manifestSha256,
  envelope,
  encryptedObject,
  submissionId = createRandomUuid(),
}) {
  return {
    submissionId,
    protocolVersion: PROTOCOL_VERSION,
    recordClass: "IMPORTED_FILE",
    recordSha256,
    manifestSha256,
    encryptedManifest: envelope,
    encryptedObject,
  };
}

export function createPrivateRecoveryKit({
  manifest,
  envelope,
  recoveryKey,
  encryptedObject,
  recoveryToken,
  serverResponse,
}) {
  return {
    schemaVersion: "sitesealed.private-recovery-kit.v1.2",
    warning:
      "PRIVATE: this file contains the manifest/original decryption key and the private storage recovery token. Keep it confidential and separate from the original file.",
    createdAt: new Date().toISOString(),
    record: serverResponse.record,
    links: serverResponse.links,
    encryptedManifest: envelope,
    manifestEncryption: {
      algorithm: "AES-256-GCM",
      keyEncoding: "base64-raw-256-bit",
      key: recoveryKey,
    },
    encryptedOriginal: {
      ...encryptedObject,
      keyEncoding: "base64-raw-256-bit",
      key: recoveryKey,
      retrieval: {
        method: "POST",
        url: serverResponse.links.encryptedOriginal,
        requestBody: { recoveryToken },
      },
    },
    manifest,
    scope: serverResponse.scope,
  };
}

export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
