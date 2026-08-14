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

export async function sha256CanonicalJson(value) {
  return sha256Bytes(new TextEncoder().encode(stableStringify(value)));
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
    const currentAlpha = [
      "sitesealed.receipt.v1.4-alpha.1",
      "sitesealed.receipt.v1.5-alpha.1",
    ].includes(record?.receipt?.schemaVersion);
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
    throw new Error("This alpha workflow accepts files up to 25 MB.");
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

export function buildLiveCaptureManifest(
  file,
  { projectReference, description, capture },
) {
  if (!(file instanceof Blob) || !capture?.challenge || !capture?.location) {
    throw new Error("A fresh camera capture, server challenge and location fix are required.");
  }
  const latitude = Number(capture.location.latitude);
  const longitude = Number(capture.location.longitude);
  const accuracyMeters = Number(capture.location.accuracyMeters);
  if (
    !Number.isFinite(latitude) ||
    latitude < -90 ||
    latitude > 90 ||
    !Number.isFinite(longitude) ||
    longitude < -180 ||
    longitude > 180 ||
    !Number.isFinite(accuracyMeters) ||
    accuracyMeters < 0
  ) {
    throw new Error("The browser did not return a usable geolocation fix.");
  }
  return {
    schemaVersion: "sitesealed.capture-manifest.v1.5-alpha.1",
    recordClass: "LIVE_CAPTURE_WEB",
    privacy: {
      plaintextOriginalTransferred: false,
      encryptedOriginalStored: true,
      encryptionKeyTransferred: false,
      preciseCoordinatesStoredInsideEncryptedManifest: true,
    },
    file: {
      name: file.name,
      size: file.size,
      mediaType: file.type || "image/jpeg",
    },
    context: {
      projectReference: projectReference.trim(),
      description: description.trim(),
    },
    capture: {
      workflow: "WEB_CAMERA_CONTEXT_BOUND_ALPHA",
      capturedAtDevice: capture.capturedAt,
      camera: {
        source: "MEDIADEVICES_GETUSERMEDIA",
        facingMode: capture.cameraFacingMode,
        width: capture.width,
        height: capture.height,
      },
      challenge: {
        challengeId: capture.challengeId,
        issuedAt: capture.issuedAt,
        captureExpiresAt: capture.captureExpiresAt,
        timeAuthority: "SITESEALED_SERVER_CHALLENGE",
      },
      time: {
        deviceClockValue: capture.capturedAt,
        serverClockDeltaAtChallengeReceiptMs: capture.clockDeltaMs,
        attestation: "SERVER_CHALLENGE_WINDOW",
      },
      location: {
        latitude,
        longitude,
        accuracyMeters,
        altitudeMeters: capture.location.altitudeMeters,
        altitudeAccuracyMeters: capture.location.altitudeAccuracyMeters,
        headingDegrees: capture.location.headingDegrees,
        speedMetersPerSecond: capture.location.speedMetersPerSecond,
        measuredAtDevice: capture.location.measuredAt,
        source: "W3C_GEOLOCATION",
        attestation: "BROWSER_GEOLOCATION_NOT_HARDWARE_ATTESTED",
      },
      device: {
        attestation: "NOT_AVAILABLE_WEB_ALPHA",
        limitation:
          "The browser cannot provide hardware-backed camera or device attestation.",
      },
      account: {
        binding: "SERVER_VERIFIED_GOOGLE_SESSION_PSEUDONYMOUS_REFERENCE",
      },
    },
    client: {
      workflow: "WEB_LIVE_CAPTURE_V1",
      manifestCreatedAt: new Date().toISOString(),
      serverChallengeBound: true,
      accountSessionBound: true,
      captureAttested: false,
      deviceAttested: false,
      locationAttested: false,
    },
  };
}

export function createCaptureProof(capture) {
  if (!capture?.challenge || !capture?.location) {
    throw new Error("The context-bound capture proof is incomplete.");
  }
  return {
    challenge: capture.challenge,
    capturedAt: capture.capturedAt,
    locationMeasuredAt: capture.location.measuredAt,
    locationAccuracyMeters: capture.location.accuracyMeters,
    clockDeltaMs: capture.clockDeltaMs,
    cameraFacingMode: capture.cameraFacingMode,
    deviceAttestation: "NOT_AVAILABLE_WEB_ALPHA",
    locationAttestation: "BROWSER_GEOLOCATION_NOT_HARDWARE_ATTESTED",
    timeAttestation: "SERVER_CHALLENGE_WINDOW",
    coordinatesManifestBound: true,
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

async function decryptAesGcm(ciphertext, rawKey, iv) {
  if (globalThis.crypto.subtle) {
    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      rawKey,
      "AES-GCM",
      false,
      ["decrypt"],
    );
    const plaintext = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext,
    );
    return new Uint8Array(plaintext);
  }
  return gcm(rawKey, iv).decrypt(ciphertext);
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
    throw new Error("This alpha workflow accepts files from 1 byte up to 25 MB.");
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
  recordClass = "IMPORTED_FILE",
  captureProof = null,
}) {
  const request = {
    submissionId,
    protocolVersion: PROTOCOL_VERSION,
    recordClass,
    recordSha256,
    manifestSha256,
    encryptedManifest: envelope,
    encryptedObject,
  };
  if (recordClass === "LIVE_CAPTURE_WEB") request.captureProof = captureProof;
  return request;
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

function recoveryKitBytes(value, expectedLength, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`The private recovery kit is missing ${label}.`);
  }
  let bytes;
  try {
    bytes = base64ToBytes(value);
  } catch {
    throw new Error(`The private recovery kit contains an invalid ${label}.`);
  }
  if (bytes.length !== expectedLength) {
    throw new Error(`The private recovery kit contains an invalid ${label}.`);
  }
  return bytes;
}

function recoveryFileName(value, recordId) {
  const name = String(value ?? "")
    .split(/[\\/]/)
    .at(-1)
    .trim()
    .slice(0, 255);
  return name || `SiteSealed_${recordId}_original`;
}

function recoveryMediaType(value) {
  const mediaType = String(value ?? "").trim().toLowerCase();
  return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mediaType)
    ? mediaType
    : "application/octet-stream";
}

export async function recoverOriginalFromPrivateRecoveryKit({
  recoveryKit,
  record,
  fetchImpl = globalThis.fetch?.bind(globalThis),
}) {
  if (
    recoveryKit?.schemaVersion !== "sitesealed.private-recovery-kit.v1.2" ||
    !recoveryKit?.manifest ||
    !recoveryKit?.record ||
    !recoveryKit?.encryptedOriginal
  ) {
    throw new Error("This is not a supported SiteSealed private recovery kit.");
  }
  const recordId = String(record?.recordId ?? "");
  if (!recordId || recoveryKit.record.recordId !== recordId) {
    throw new Error("This private recovery kit belongs to a different record.");
  }
  if (
    recoveryKit.record.sha256 !== record.sha256 ||
    recoveryKit.record.manifestSha256 !== record.manifestSha256 ||
    recoveryKit.manifest.recordClass !== record.recordClass
  ) {
    throw new Error("The private recovery kit does not match the public evidence record.");
  }

  const manifestSha256 = await sha256CanonicalJson(recoveryKit.manifest);
  if (manifestSha256 !== record.manifestSha256) {
    throw new Error("The private recovery kit manifest failed its recorded SHA-256 check.");
  }

  const encryptedOriginal = recoveryKit.encryptedOriginal;
  const publicStorage = record.storage ?? {};
  if (
    encryptedOriginal.algorithm !== "AES-256-GCM" ||
    encryptedOriginal.ciphertextSha256 !== publicStorage.ciphertextSha256 ||
    Number(encryptedOriginal.ciphertextBytes) !== Number(publicStorage.ciphertextBytes) ||
    Number(encryptedOriginal.plaintextBytes) !== Number(publicStorage.plaintextBytes)
  ) {
    throw new Error("The recovery metadata does not match the stored encrypted original.");
  }
  const plaintextBytes = Number(encryptedOriginal.plaintextBytes);
  const ciphertextBytes = Number(encryptedOriginal.ciphertextBytes);
  if (
    !Number.isSafeInteger(plaintextBytes) ||
    plaintextBytes <= 0 ||
    plaintextBytes > MAX_FILE_BYTES ||
    ciphertextBytes !== plaintextBytes + 16 ||
    Number(recoveryKit.manifest.file?.size) !== plaintextBytes
  ) {
    throw new Error("The recovery kit contains inconsistent original-file sizes.");
  }

  const recoveryKey = recoveryKit.manifestEncryption?.key;
  if (
    recoveryKit.manifestEncryption?.algorithm !== "AES-256-GCM" ||
    recoveryKit.manifestEncryption?.keyEncoding !== "base64-raw-256-bit" ||
    encryptedOriginal.keyEncoding !== "base64-raw-256-bit" ||
    encryptedOriginal.key !== recoveryKey
  ) {
    throw new Error("The private recovery kit contains inconsistent encryption keys.");
  }
  const rawKey = recoveryKitBytes(recoveryKey, 32, "AES-256 key");
  const iv = recoveryKitBytes(encryptedOriginal.iv, 12, "original-file IV");
  const recoveryToken = encryptedOriginal.retrieval?.requestBody?.recoveryToken;
  recoveryKitBytes(recoveryToken, 32, "private recovery token");
  if (typeof fetchImpl !== "function") {
    throw new Error("This browser cannot retrieve the encrypted original.");
  }

  // Deliberately derive the same-origin endpoint instead of trusting a URL
  // contained in an imported private kit. This prevents recovery-token exfiltration.
  const endpoint = `/api/records/${encodeURIComponent(recordId)}/encrypted-original`;
  const response = await fetchImpl(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ recoveryToken }),
    cache: "no-store",
    credentials: "same-origin",
  });
  if (!response?.ok) {
    let message = "The encrypted original could not be retrieved.";
    try {
      const payload = JSON.parse(await response.text());
      if (typeof payload?.message === "string" && payload.message.trim()) {
        message = payload.message;
      }
    } catch {
      // Keep the controlled message when the server response is not JSON.
    }
    throw new Error(message);
  }

  const ciphertext = new Uint8Array(await response.arrayBuffer());
  if (
    ciphertext.length !== ciphertextBytes ||
    await sha256Bytes(ciphertext) !== encryptedOriginal.ciphertextSha256
  ) {
    throw new Error("The retrieved encrypted original failed its SHA-256 check.");
  }

  let plaintext;
  try {
    plaintext = await decryptAesGcm(ciphertext, rawKey, iv);
  } catch {
    throw new Error("The encrypted original could not be authenticated and decrypted.");
  }
  if (
    plaintext.length !== plaintextBytes ||
    await sha256Bytes(plaintext) !== record.sha256
  ) {
    throw new Error("The recovered original does not match the recorded SHA-256 digest.");
  }

  const captureTime = recoveryKit.manifest.capture?.capturedAtDevice;
  const importedTime = recoveryKit.manifest.file?.lastModifiedClientValue;
  const parsedTime = Date.parse(captureTime || importedTime || "");
  return new File(
    [plaintext],
    recoveryFileName(recoveryKit.manifest.file?.name, recordId),
    {
      type: recoveryMediaType(recoveryKit.manifest.file?.mediaType),
      lastModified: Number.isFinite(parsedTime) ? parsedTime : 0,
    },
  );
}

export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
