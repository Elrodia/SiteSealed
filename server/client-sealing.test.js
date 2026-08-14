import assert from "node:assert/strict";
import { File } from "node:buffer";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { gcm } from "@noble/ciphers/aes.js";
import {
  PDFArray,
  PDFDict,
  PDFDocument,
  PDFName,
  PDFRawStream,
  decodePDFRawStream,
} from "pdf-lib";
import {
  evidenceReportFileName,
  generateSiteSealedEvidenceReport,
} from "../client/src/evidence-report.js";
import {
  buildLiveCaptureManifest,
  buildManifest,
  createCaptureProof,
  createEncryptedUploadHeaders,
  createPrivateRecoveryKit,
  createRecoveryToken,
  createSealRequest,
  createUploadGrantRequest,
  encryptManifest,
  encryptOriginal,
  recoverOriginalFromPrivateRecoveryKit,
  recalculateEvidenceDigest,
  sha256CanonicalJson,
  sha256File,
  stableStringify,
  verifyPublicProofArtifacts,
} from "../client/src/sealing.js";
import { buildMerkleTree } from "./merkle.js";
import { createEvidenceDigest } from "./records.js";

function fromBase64(value) {
  return Uint8Array.from(Buffer.from(value, "base64"));
}

async function extractPdfAttachments(bytes) {
  const document = await PDFDocument.load(bytes);
  const names = document.catalog.lookup(PDFName.of("Names"), PDFDict);
  const embeddedFiles = names.lookup(PDFName.of("EmbeddedFiles"), PDFDict);
  const entries = embeddedFiles.lookup(PDFName.of("Names"), PDFArray);
  const attachments = new Map();
  for (let index = 0; index < entries.size(); index += 2) {
    const name = entries.lookup(index).decodeText();
    const fileSpec = entries.lookup(index + 1, PDFDict);
    const streams = fileSpec.lookup(PDFName.of("EF"), PDFDict);
    const stream = streams.lookup(PDFName.of("F"), PDFRawStream);
    attachments.set(name, decodePDFRawStream(stream).decode());
  }
  return { document, attachments };
}

test("the browser workflow hashes the selected file locally", async () => {
  const file = new File(["abc"], "inspection.txt", {
    type: "text/plain",
    lastModified: Date.parse("2026-08-11T20:00:00.000Z"),
  });
  const digest = await sha256File(file);
  assert.equal(
    digest,
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("the client encrypts the canonical manifest and keeps the key outside the API request", async () => {
  const file = new File(["construction record"], "IMG_0001.JPG", {
    type: "image/jpeg",
    lastModified: Date.parse("2026-08-11T20:00:00.000Z"),
  });
  const manifest = buildManifest(file, {
    projectReference: "RBP-C-2026",
    description: "Foundation inspection",
  });
  const encrypted = await encryptManifest(manifest);
  const encryptedFile = await encryptOriginal(file, encrypted.recoveryKey);
  const recoveryToken = await createRecoveryToken();
  const encryptedObject = {
    ...encryptedFile.envelope,
    objectKey:
      `sealed/v1.2/123e4567-e89b-42d3-a456-426614174000/` +
      `${encryptedFile.envelope.ciphertextSha256.slice(0, 2)}/` +
      `${encryptedFile.envelope.ciphertextSha256}.ssenc`,
    recoveryTokenSha256: recoveryToken.sha256,
  };
  const request = createSealRequest({
    recordSha256: await sha256File(file),
    manifestSha256: encrypted.manifestSha256,
    envelope: encrypted.envelope,
    encryptedObject,
    submissionId: "123e4567-e89b-42d3-a456-426614174000",
  });

  assert.equal(Object.hasOwn(request, "recoveryKey"), false);
  assert.equal(JSON.stringify(request).includes("Foundation inspection"), false);
  assert.equal(request.encryptedManifest.algorithm, "AES-256-GCM");
  assert.equal(request.encryptedObject.algorithm, "AES-256-GCM");

  const key = await crypto.subtle.importKey(
    "raw",
    fromBase64(encrypted.recoveryKey),
    "AES-GCM",
    false,
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(encrypted.envelope.iv) },
    key,
    fromBase64(encrypted.envelope.ciphertext),
  );
  assert.equal(new TextDecoder().decode(plaintext), stableStringify(manifest));

  const originalPlaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(encryptedFile.envelope.iv) },
    key,
    encryptedFile.ciphertext,
  );
  assert.equal(
    new TextDecoder().decode(originalPlaintext),
    "construction record",
  );
  assert.equal(encryptedFile.ciphertext.length, file.size + 16);

  const headers = createEncryptedUploadHeaders({
    recordSha256: request.recordSha256,
    encryptedOriginal: encryptedFile,
    recoveryTokenSha256: recoveryToken.sha256,
    uploadGrant: "grant-token",
  });
  assert.equal(headers["content-type"], "application/octet-stream");
  assert.equal(
    headers["x-sitesealed-cipher-sha256"],
    encryptedFile.envelope.ciphertextSha256,
  );
  assert.equal(headers["x-sitesealed-upload-grant"], "grant-token");
  assert.deepEqual(
    createUploadGrantRequest({
      submissionId: request.submissionId,
      recordSha256: request.recordSha256,
      encryptedOriginal: encryptedFile,
      recoveryTokenSha256: recoveryToken.sha256,
    }),
    {
      submissionId: request.submissionId,
      recordSha256: request.recordSha256,
      ciphertextSha256: encryptedFile.envelope.ciphertextSha256,
      ciphertextBytes: encryptedFile.envelope.ciphertextBytes,
      plaintextBytes: encryptedFile.envelope.plaintextBytes,
      iv: encryptedFile.envelope.iv,
      recoveryTokenSha256: recoveryToken.sha256,
    },
  );
  assert.equal(JSON.stringify(request).includes(recoveryToken.token), false);
});

test("the private recovery kit alone restores an exact live capture from private storage", async () => {
  const capturedAt = "2026-08-14T20:15:05.000Z";
  const originalBytes = Buffer.from("exact live-camera JPEG bytes");
  const originalFile = new File(
    [originalBytes],
    "SiteSealed_CAPTURE_2026-08-14T20-15-05Z.jpg",
    { type: "image/jpeg", lastModified: Date.parse(capturedAt) },
  );
  const manifest = {
    schemaVersion: "sitesealed.capture-manifest.v1.5-alpha.1",
    recordClass: "LIVE_CAPTURE_WEB",
    file: {
      name: originalFile.name,
      size: originalFile.size,
      mediaType: originalFile.type,
    },
    capture: { capturedAtDevice: capturedAt },
  };
  const encryptedManifest = await encryptManifest(manifest);
  const encryptedOriginal = await encryptOriginal(
    originalFile,
    encryptedManifest.recoveryKey,
  );
  const recoveryToken = await createRecoveryToken();
  const recordId = "SR-20260814-RECOVERYKITONLY";
  const record = {
    recordId,
    recordClass: "LIVE_CAPTURE_WEB",
    sha256: await sha256File(originalFile),
    manifestSha256: encryptedManifest.manifestSha256,
    storage: {
      state: "STORED_ENCRYPTED",
      ciphertextSha256: encryptedOriginal.envelope.ciphertextSha256,
      ciphertextBytes: encryptedOriginal.envelope.ciphertextBytes,
      plaintextBytes: encryptedOriginal.envelope.plaintextBytes,
    },
  };
  const recoveryKit = createPrivateRecoveryKit({
    manifest,
    envelope: encryptedManifest.envelope,
    recoveryKey: encryptedManifest.recoveryKey,
    encryptedObject: encryptedOriginal.envelope,
    recoveryToken: recoveryToken.token,
    serverResponse: {
      record,
      links: {
        encryptedOriginal: "https://attacker.invalid/collect-recovery-token",
      },
      scope: {},
    },
  });

  let requestedUrl;
  let requestedOptions;
  const recovered = await recoverOriginalFromPrivateRecoveryKit({
    recoveryKit,
    record,
    fetchImpl: async (url, options) => {
      requestedUrl = url;
      requestedOptions = options;
      return new Response(encryptedOriginal.ciphertext, { status: 200 });
    },
  });

  assert.equal(
    requestedUrl,
    `/api/records/${recordId}/encrypted-original`,
  );
  assert.equal(requestedOptions.method, "POST");
  assert.deepEqual(JSON.parse(requestedOptions.body), {
    recoveryToken: recoveryToken.token,
  });
  assert.equal(recovered.name, originalFile.name);
  assert.equal(recovered.type, "image/jpeg");
  assert.equal(recovered.lastModified, Date.parse(capturedAt));
  assert.deepEqual(Buffer.from(await recovered.arrayBuffer()), originalBytes);

  const corruptedCiphertext = Uint8Array.from(encryptedOriginal.ciphertext);
  corruptedCiphertext[0] ^= 0xff;
  await assert.rejects(
    recoverOriginalFromPrivateRecoveryKit({
      recoveryKit,
      record,
      fetchImpl: async () => new Response(corruptedCiphertext, { status: 200 }),
    }),
    /encrypted original failed its SHA-256 check/,
  );
});

test("the live web manifest binds a fresh challenge, browser context and honest limitations", async () => {
  const file = new File(["fresh frame"], "SiteSealed_CAPTURE.jpg", {
    type: "image/jpeg",
    lastModified: Date.parse("2026-08-14T10:00:05.000Z"),
  });
  const capture = {
    challenge: `123e4567-e89b-42d3-a456-426614174000.${"A".repeat(43)}`,
    challengeId: "123e4567-e89b-42d3-a456-426614174000",
    issuedAt: "2026-08-14T10:00:00.000Z",
    captureExpiresAt: "2026-08-14T10:02:00.000Z",
    capturedAt: "2026-08-14T10:00:05.000Z",
    clockDeltaMs: 19,
    cameraFacingMode: "environment",
    width: 1920,
    height: 1080,
    location: {
      latitude: -4.9686,
      longitude: -39.0154,
      accuracyMeters: 8.2,
      altitudeMeters: null,
      altitudeAccuracyMeters: null,
      headingDegrees: null,
      speedMetersPerSecond: null,
      measuredAt: "2026-08-14T10:00:04.000Z",
    },
  };
  const manifest = buildLiveCaptureManifest(file, {
    projectReference: "QUIXADA-2026",
    description: "Fresh browser capture",
    capture,
  });
  const proof = createCaptureProof(capture);

  assert.equal(manifest.recordClass, "LIVE_CAPTURE_WEB");
  assert.equal(manifest.capture.location.latitude, -4.9686);
  assert.equal(manifest.client.serverChallengeBound, true);
  assert.equal(manifest.client.captureAttested, false);
  assert.equal(manifest.client.deviceAttested, false);
  assert.equal(manifest.client.locationAttested, false);
  assert.equal(proof.challenge, capture.challenge);
  assert.equal(proof.coordinatesManifestBound, true);
  assert.match(await sha256CanonicalJson(manifest), /^[a-f0-9]{64}$/);

  const request = createSealRequest({
    recordSha256: await sha256File(file),
    manifestSha256: await sha256CanonicalJson(manifest),
    envelope: {
      version: 1,
      algorithm: "AES-256-GCM",
      iv: Buffer.alloc(12).toString("base64"),
      ciphertext: Buffer.alloc(32).toString("base64"),
    },
    encryptedObject: {},
    submissionId: "123e4567-e89b-42d3-a456-426614174000",
    recordClass: "LIVE_CAPTURE_WEB",
    captureProof: proof,
  });
  assert.equal(request.recordClass, "LIVE_CAPTURE_WEB");
  assert.equal(request.captureProof.deviceAttestation, "NOT_AVAILABLE_WEB_ALPHA");
});

test("the local cryptography fallback works outside a secure Web Crypto context", async () => {
  const originalCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: {
      getRandomValues: originalCrypto.getRandomValues.bind(originalCrypto),
    },
  });

  try {
    const file = new File(["fallback"], "fallback.txt", {
      type: "text/plain",
      lastModified: Date.parse("2026-08-11T20:00:00.000Z"),
    });
    assert.equal(
      await sha256File(file),
      "5c7ee2074b65853f71fc5a01ce194ff26deedf6daacdb715c6beefdfd3f31b35",
    );

    const manifest = buildManifest(file, {
      projectReference: "FALLBACK-QA",
      description: "No subtle crypto available",
    });
    const encrypted = await encryptManifest(manifest);
    const plaintext = gcm(
      fromBase64(encrypted.recoveryKey),
      fromBase64(encrypted.envelope.iv),
    ).decrypt(fromBase64(encrypted.envelope.ciphertext));
    assert.equal(new TextDecoder().decode(plaintext), stableStringify(manifest));
  } finally {
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: originalCrypto,
    });
  }
});

test("the browser independently recalculates the evidence digest and Ethereum Merkle binding", async () => {
  const recordSha256 =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  const manifestSha256 = "1".repeat(64);
  const evidenceDigest = createEvidenceDigest({
    recordSha256,
    manifestSha256,
  });
  assert.equal(
    await recalculateEvidenceDigest(recordSha256, manifestSha256),
    evidenceDigest,
  );

  const tree = buildMerkleTree([
    { recordId: "SR-BROWSER-1", evidenceDigest },
    { recordId: "SR-BROWSER-2", evidenceDigest: "2".repeat(64) },
  ]);
  const member = tree.members[0];
  const record = {
    sha256: recordSha256,
    manifestSha256,
    evidenceDigest,
    receipt: { schemaVersion: "sitesealed.receipt.v1.4-alpha.1" },
    chainRail: {
      anchor: `0x${"3".repeat(64)}`,
      chainId: 1,
      merkleRoot: tree.root,
      leafHash: member.leafHash,
      inclusionPath: member.inclusionPath,
      transactionInput: `0x53534c4401${tree.root}`,
    },
  };

  assert.deepEqual(await verifyPublicProofArtifacts(record), {
    state: "PASS",
    evidenceDigest: "PASS",
    merkleInclusion: "PASS",
    transactionBinding: "PASS",
  });

  record.chainRail.transactionInput = `0x53534c4401${"f".repeat(64)}`;
  assert.deepEqual(await verifyPublicProofArtifacts(record), {
    state: "FAIL",
    evidenceDigest: "PASS",
    merkleInclusion: "PASS",
    transactionBinding: "MISMATCH",
  });

  delete record.chainRail.transactionInput;
  assert.deepEqual(await verifyPublicProofArtifacts(record), {
    state: "FAIL",
    evidenceDigest: "PASS",
    merkleInclusion: "PASS",
    transactionBinding: "MISSING",
  });
});

test("the browser reports a valid local receipt while its external anchor is pending", async () => {
  const recordSha256 = "4".repeat(64);
  const manifestSha256 = "5".repeat(64);
  const record = {
    sha256: recordSha256,
    manifestSha256,
    evidenceDigest: createEvidenceDigest({ recordSha256, manifestSha256 }),
    receipt: { schemaVersion: "sitesealed.receipt.v1.4-alpha.1" },
    chainRail: { anchor: null, merkleRoot: null, inclusionPath: null },
  };

  assert.deepEqual(await verifyPublicProofArtifacts(record), {
    state: "RECEIPT_VALID_EXTERNAL_PENDING",
    evidenceDigest: "PASS",
    merkleInclusion: "NOT_ATTACHED",
    transactionBinding: "NOT_ATTACHED",
  });
});

test("the browser creates one Evidence Report containing the visible and exact original", async () => {
  const originalBytes = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Z0kYAAAAASUVORK5CYII=",
    "base64",
  );
  const originalFile = new File([originalBytes], "site-inspection.png", {
    type: "image/png",
    lastModified: Date.parse("2026-08-13T20:00:00.000Z"),
  });
  const sha256 = await sha256File(originalFile);
  const recordId = "SR-20260814-CANONICAL";
  const timestampToken = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]);
  const verification = {
    alphaComplete: true,
    record: {
      recordId,
      sha256,
      manifestSha256: "1".repeat(64),
      evidenceDigest: "2".repeat(64),
      receivedAt: "2026-08-13T20:01:00.000Z",
      classification: "Imported file - web workflow",
      qualifiedRail: {
        state: "SANDBOX_TOKEN_ISSUED",
        signatureVerification: "VALID",
        certificateChainVerification: "VALID_TO_PINNED_SANDBOX_ROOT",
        tokenSha256: "3".repeat(64),
      },
      chainRail: {
        state: "FINALIZED",
        block: 23_456_789,
        status: "Mainnet transaction finalized",
      },
    },
    scope: {
      proves: "The attached original is byte-identical to the recorded digest.",
      doesNotProve: "Authorship, live capture, location or truthfulness.",
    },
  };
  const proofBundle = { schemaVersion: "sitesealed.proof-bundle.v1", recordId };

  const reportBytes = await generateSiteSealedEvidenceReport({
    originalFile,
    verification,
    proofBundle,
    timestampToken,
    baseUrl: "https://app.sitesealed.com",
    generatedAt: new Date("2026-08-14T00:00:00.000Z"),
  });
  assert.equal(Buffer.from(reportBytes).subarray(0, 5).toString("ascii"), "%PDF-");
  assert.equal(
    evidenceReportFileName(recordId),
    "SiteSealed_SR-20260814-CANONICAL_Evidence_Report.pdf",
  );

  const { document, attachments } = await extractPdfAttachments(reportBytes);
  assert.equal(document.getPageCount(), 2);
  assert.equal(document.getTitle(), `EVIDENCE REPORT — SiteSealed ${recordId}`);
  assert.deepEqual(
    Buffer.from(attachments.get("SiteSealed_ORIGINAL_site-inspection.png")),
    originalBytes,
  );
  assert.deepEqual(
    Buffer.from(attachments.get(`SiteSealed_${recordId}_timestamp.tsr`)),
    Buffer.from(timestampToken),
  );
  const manifest = JSON.parse(
    Buffer.from(
      attachments.get(`SiteSealed_${recordId}_report-manifest.json`),
    ).toString("utf8"),
  );
  assert.equal(manifest.original.sha256, sha256);
  assert.equal(manifest.original.byteLength, originalBytes.length);
  assert.equal(manifest.original.byteIdentityVerified, true);
  assert.equal(manifest.locale, "en-US");
});

test("a live-capture Evidence Report embeds and cross-checks its private canonical manifest", async () => {
  const originalBytes = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Z0kYAAAAASUVORK5CYII=",
    "base64",
  );
  const capturedAt = "2026-08-14T10:00:05.000Z";
  const originalFile = new File(
    [originalBytes],
    "SiteSealed_CAPTURE_2026-08-14T10-00-05Z.png",
    { type: "image/png", lastModified: Date.parse(capturedAt) },
  );
  const capture = {
    challenge: `123e4567-e89b-42d3-a456-426614174000.${"A".repeat(43)}`,
    challengeId: "123e4567-e89b-42d3-a456-426614174000",
    issuedAt: "2026-08-14T10:00:00.000Z",
    captureExpiresAt: "2026-08-14T10:02:00.000Z",
    capturedAt,
    clockDeltaMs: 12,
    cameraFacingMode: "environment",
    width: 1920,
    height: 1080,
    location: {
      latitude: -4.9686,
      longitude: -39.0154,
      accuracyMeters: 7.4,
      altitudeMeters: null,
      altitudeAccuracyMeters: null,
      headingDegrees: null,
      speedMetersPerSecond: null,
      measuredAt: "2026-08-14T10:00:04.000Z",
    },
  };
  const captureManifest = buildLiveCaptureManifest(originalFile, {
    projectReference: "QUIXADA-2026",
    description: "Context-bound browser capture",
    capture,
  });
  const recordId = "SR-20260814-LIVECAPTURE";
  const accountReference = "9".repeat(64);
  const captureContext = {
    schemaVersion: "sitesealed.capture-context.v1.5-alpha.1",
    workflow: "WEB_CAMERA_CONTEXT_BOUND_ALPHA",
    challengeId: capture.challengeId,
    challengeIssuedAt: capture.issuedAt,
    challengeCaptureExpiresAt: capture.captureExpiresAt,
    timeAuthority: "SITESEALED_SERVER_CHALLENGE",
    capturedAt,
    clientClockDeltaMs: capture.clockDeltaMs,
    cameraFacingMode: capture.cameraFacingMode,
    location: {
      coordinatesManifestBound: true,
      measuredAt: capture.location.measuredAt,
      accuracyMeters: capture.location.accuracyMeters,
      attestation: "BROWSER_GEOLOCATION_NOT_HARDWARE_ATTESTED",
    },
    deviceAttestation: "NOT_AVAILABLE_WEB_ALPHA",
    timeAttestation: "SERVER_CHALLENGE_WINDOW",
    account: { provider: "GOOGLE", accountReference },
  };
  const verification = {
    alphaComplete: false,
    record: {
      recordId,
      recordClass: "LIVE_CAPTURE_WEB",
      classification: "Context-bound web camera capture - alpha",
      sha256: await sha256File(originalFile),
      manifestSha256: await sha256CanonicalJson(captureManifest),
      evidenceDigest: "2".repeat(64),
      receivedAt: "2026-08-14T10:00:15.000Z",
      captureContext,
      qualifiedRail: { state: "NOT_ISSUED" },
      chainRail: { state: "NOT_ANCHORED" },
    },
    scope: {
      proves: "The original and canonical manifest match the recorded digests.",
      attests: "The server bound the submitted context to a fresh challenge.",
      doesNotProve: "No physical sensor, GNSS coordinate or unstaged scene is proven.",
    },
  };

  const reportBytes = await generateSiteSealedEvidenceReport({
    originalFile,
    captureManifest,
    verification,
    proofBundle: { schemaVersion: "sitesealed.proof-bundle.v1.5-alpha.1" },
    baseUrl: "https://app.sitesealed.com",
    generatedAt: new Date("2026-08-14T10:05:00.000Z"),
  });
  const { document, attachments } = await extractPdfAttachments(reportBytes);
  assert.equal(document.getPageCount(), 3);
  const manifestAttachment = JSON.parse(
    Buffer.from(
      attachments.get(`SiteSealed_${recordId}_capture-manifest.json`),
    ).toString("utf8"),
  );
  assert.deepEqual(manifestAttachment, captureManifest);

  const tamperedManifest = structuredClone(captureManifest);
  tamperedManifest.capture.location.latitude = 50.6451;
  await assert.rejects(
    generateSiteSealedEvidenceReport({
      originalFile,
      captureManifest: tamperedManifest,
      verification,
      proofBundle: {},
    }),
    /capture manifest does not match the recorded SHA-256/,
  );
});

test("the Evidence Report refuses a different original", async () => {
  const recordedFile = new File(["recorded"], "recorded.txt", {
    type: "text/plain",
  });
  const differentFile = new File(["different"], "different.txt", {
    type: "text/plain",
  });
  await assert.rejects(
    generateSiteSealedEvidenceReport({
      originalFile: differentFile,
      verification: {
        record: {
          recordId: "SR-20260814-MISMATCH",
          sha256: await sha256File(recordedFile),
        },
      },
      proofBundle: {},
    }),
    /does not match the recorded SHA-256/,
  );
});

test("the browser uses Google Identity Services and sends SiteSealed CSRF tokens", async () => {
  const source = await readFile(
    new URL("../client/src/App.jsx", import.meta.url),
    "utf8",
  );
  const desktopStyles = await readFile(
    new URL("../client/src/App-desktop.css", import.meta.url),
    "utf8",
  );
  assert.match(source, /google\.accounts\.id\.renderButton/);
  assert.match(source, /ux_mode: "redirect"/);
  assert.match(source, /gsi\/client\?hl=\$\{encodeURIComponent\(googleLocale\)\}/);
  assert.match(source, /googleScript\.nonce = cspNonce/);
  assert.match(source, /color_scheme: "dark"/);
  assert.match(source, /type: "standard"/);
  assert.match(source, /theme: "outline_dark"/);
  assert.match(source, /size: "large"/);
  assert.match(source, /width: 400/);
  assert.match(source, /locale: googleLocale/);
  assert.match(source, /function GoogleMark\(\)/);
  assert.match(source, /Continue with Google before uploading/);
  assert.match(source, /generateSiteSealedEvidenceReport/);
  assert.match(source, /Download SiteSealed Evidence Report/);
  assert.match(source, /onChange=\{selectComparisonFile\}/);
  assert.match(source, /onChange=\{selectPrivateRecoveryKit\}/);
  assert.match(source, /Choose recovery kit/);
  assert.match(source, /recoverOriginalFromPrivateRecoveryKit/);
  assert.match(source, /No separate photo is required/);
  assert.match(source, /the private recovery kit is all you need/);
  assert.match(
    source,
    /nextFile && status === "success" && result && !result\.specimen[\s\S]*?runVerification\(result\.record\.recordId, nextFile\)/,
  );
  assert.match(source, /Its hash is checked automatically/);
  assert.doesNotMatch(source, /links\.receiptPdf/);
  assert.match(
    source,
    /className="google-signin-visual button button--amber"/,
  );
  assert.match(
    source,
    /auth\.status === "ready" && auth\.configured && !auth\.authenticated[\s\S]*?<GoogleSignInControl auth=\{auth\} \/>/,
  );
  assert.doesNotMatch(source, /"Sign in to seal"/);
  assert.match(
    desktopStyles,
    /\.account-access\s*\{[^}]*background: #0d2232;/s,
  );
  assert.match(
    desktopStyles,
    /\.google-signin-button\s*\{[^}]*width: 100%;[^}]*max-width: 400px;[^}]*height: 52px;[^}]*overflow: hidden;[^}]*opacity: 0;/s,
  );
  assert.match(
    desktopStyles,
    /\.google-signin-visual\s*\{[^}]*width: 100%;[^}]*min-height: 52px;[^}]*pointer-events: none;/s,
  );
  assert.doesNotMatch(desktopStyles, /img,\s*\nsvg\s*\{/);
  assert.match(source, /"x-sitesealed-csrf": auth\.csrfToken/);
  assert.doesNotMatch(source, /x-sitesealed-deposit-access/);
  assert.doesNotMatch(source, /depositAccess/);
});
