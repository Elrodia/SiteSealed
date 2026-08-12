import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { after, before, test } from "node:test";
import { createMemoryCoordinator } from "./coordination.js";
import { createApp } from "./server.js";
import { createMemoryRecordStore } from "./specimen.js";

let server;
let baseUrl;
let sequence = 0;
const TEST_UPLOAD = Symbol("testUpload");

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function validRequest(overrides = {}) {
  sequence += 1;
  const suffix = sequence.toString(16).padStart(12, "0");
  const request = {
    submissionId: `123e4567-e89b-42d3-a456-${suffix}`,
    protocolVersion: "1.2",
    recordClass: "IMPORTED_FILE",
    recordSha256:
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    manifestSha256:
      "7f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a09",
    encryptedManifest: {
      version: 1,
      algorithm: "AES-256-GCM",
      iv: Buffer.alloc(12, 1).toString("base64"),
      ciphertext: Buffer.alloc(32, 2).toString("base64"),
    },
    ...overrides,
  };
  const ciphertext = Buffer.alloc(32, (sequence % 250) + 1);
  const recoveryToken = Buffer.alloc(32, ((sequence + 17) % 250) + 1);
  Object.defineProperty(request, TEST_UPLOAD, {
    value: {
      ciphertext,
      recoveryToken,
      recoveryTokenSha256: sha256(recoveryToken),
      iv: Buffer.alloc(12, ((sequence + 29) % 250) + 1).toString("base64"),
      plaintextBytes: 16,
    },
  });
  return request;
}

async function createReceipt(body = validRequest()) {
  const upload = body[TEST_UPLOAD];
  if (!body.encryptedObject) {
    const uploadResponse = await fetch(
      `${baseUrl}/api/storage/uploads/${encodeURIComponent(body.submissionId)}`,
      {
        method: "PUT",
        headers: {
          "content-type": "application/octet-stream",
          "x-sitesealed-record-sha256": body.recordSha256,
          "x-sitesealed-cipher-sha256": sha256(upload.ciphertext),
          "x-sitesealed-cipher-iv": upload.iv,
          "x-sitesealed-original-bytes": String(upload.plaintextBytes),
          "x-sitesealed-recovery-token-sha256": upload.recoveryTokenSha256,
        },
        body: upload.ciphertext,
      },
    );
    const uploadPayload = await uploadResponse.json();
    assert.ok(uploadResponse.ok, JSON.stringify(uploadPayload));
    body.encryptedObject = uploadPayload.encryptedObject;
  }
  const response = await fetch(`${baseUrl}/api/records`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { response, payload: await response.json(), body, upload };
}

before(async () => {
  const app = createApp({
    recordStore: createMemoryRecordStore(),
    sealRateLimit: 100,
  });
  await new Promise((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

test("health endpoint reports the honest v1.4-alpha.6 capability boundary", async () => {
  const response = await fetch(`${baseUrl}/api/health`);
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.ok, true);
  assert.equal(payload.service, "sitesealed");
  assert.equal(payload.version, "1.4.0-alpha.6");
  assert.equal(payload.sealing.clientEncryptedObjectStorage, true);
  assert.equal(
    payload.sealing.operationalAudit,
    "POSTGRESQL_APPEND_ONLY_HASH_CHAIN",
  );
  assert.equal(payload.sealing.distributedCoordination, true);
  assert.equal(payload.sealing.qualifiedTimestamp, false);
  assert.equal(payload.sealing.publicChainAnchor, false);
  assert.equal(payload.sealing.finalSealedStatusEnabled, false);
  assert.deepEqual(payload.database, {
    mode: "memory",
    status: "not_configured",
    persistent: false,
    writable: true,
  });
  assert.deepEqual(payload.objectStorage, {
    mode: "memory",
    status: "not_configured",
    persistent: false,
    writable: true,
    private: true,
    clientEncryptedOnly: true,
  });
  assert.deepEqual(payload.auditDatabase, {
    mode: "memory",
    status: "not_configured",
    persistent: false,
    writable: true,
    appendOnly: true,
    hashChained: true,
    independentlyAnchored: false,
    latestSequence: "0",
  });
  assert.deepEqual(payload.coordination, {
    mode: "memory",
    status: "not_configured",
    persistent: false,
    writable: true,
    authoritative: false,
    distributed: false,
    rateLimiting: true,
    verificationCache: true,
    runtimeRailStatus: true,
  });
  assert.deepEqual(payload.qualifiedTimestamp, {
    mode: "disabled",
    status: "not_configured",
    provider: "Evidency",
    environment: "SANDBOX",
    legalUse: false,
  });
  assert.deepEqual(payload.publicChainAnchor, {
    mode: "disabled",
    status: "not_configured",
    network: "Ethereum mainnet",
    chainId: 1,
    writesEnabled: false,
  });
});

test("health endpoint reads operational Evidency status from the separate worker", async () => {
  const coordinator = createMemoryCoordinator();
  await coordinator.setRailRuntimeStatus("evidency", {
    mode: "evidency",
    status: "operational",
    provider: "Evidency",
    environment: "SANDBOX",
    configured: true,
    externalCallVerified: true,
    legalUse: false,
    qualificationStatus: "TEST_ONLY_NOT_QUALIFIED",
    responseValidation: "RFC3161_CMS_SIGNATURE_CHAIN_AND_DIGEST_VALID",
    signatureVerification: "VALID",
    certificateChainVerification: "VALID_TO_PINNED_SANDBOX_ROOT",
    validatorVersion: "SITESEALED_RFC3161_VALIDATOR_V1",
    revocationVerification: "NOT_CHECKED",
    dryRun: false,
    lastCheckedAt: "2026-08-12T20:00:00.000Z",
    lastSuccessAt: "2026-08-12T20:00:00.000Z",
  });
  const statusApp = createApp({
    recordStore: createMemoryRecordStore(),
    coordinator,
    sealRateLimit: 100,
  });
  const statusServer = await new Promise((resolve) => {
    const instance = statusApp.listen(0, "127.0.0.1", () => resolve(instance));
  });
  const address = statusServer.address();

  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/api/health`);
    const payload = await response.json();
    assert.equal(payload.qualifiedTimestamp.status, "operational");
    assert.equal(payload.qualifiedTimestamp.externalCallVerified, true);
    assert.equal(
      payload.sealing.qualifiedTimestamp,
      "EVIDENCY_SANDBOX_CRYPTOGRAPHICALLY_VERIFIED_TEST_ONLY",
    );
  } finally {
    await new Promise((resolve, reject) =>
      statusServer.close((error) => (error ? reject(error) : resolve())),
    );
  }
});

test("health endpoint refuses a stale pre-alpha.6 operational claim", async () => {
  const coordinator = createMemoryCoordinator();
  await coordinator.setRailRuntimeStatus("evidency", {
    mode: "evidency",
    status: "operational",
    provider: "Evidency",
    environment: "SANDBOX",
    configured: true,
    externalCallVerified: true,
    legalUse: false,
    qualificationStatus: "TEST_ONLY_NOT_QUALIFIED",
    responseValidation: "TOKEN_RECEIVED_DIGEST_BOUND_AND_STORED",
    dryRun: false,
    lastCheckedAt: "2026-08-12T20:00:00.000Z",
    lastSuccessAt: "2026-08-12T20:00:00.000Z",
  });
  const statusApp = createApp({
    recordStore: createMemoryRecordStore(),
    coordinator,
    sealRateLimit: 100,
  });
  const statusServer = await new Promise((resolve) => {
    const instance = statusApp.listen(0, "127.0.0.1", () => resolve(instance));
  });
  const address = statusServer.address();

  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/api/health`);
    const payload = await response.json();
    assert.equal(payload.qualifiedTimestamp.status, "configured");
    assert.equal(payload.qualifiedTimestamp.externalCallVerified, false);
    assert.equal(payload.sealing.qualifiedTimestamp, "EVIDENCY_SANDBOX_READY_TEST_ONLY");
  } finally {
    await new Promise((resolve, reject) =>
      statusServer.close((error) => (error ? reject(error) : resolve())),
    );
  }
});

test("a real digest receipt binds a client-encrypted original without receiving plaintext", async () => {
  const { response, payload, upload } = await createReceipt();
  assert.equal(response.status, 201);
  assert.equal(payload.ok, true);
  assert.equal(payload.created, true);
  assert.match(payload.record.recordId, /^SR-\d{8}-[A-F0-9]{24}$/);
  assert.equal(payload.record.proofLevel, "DUAL_RAIL_ALPHA_RECEIPT");
  assert.match(payload.record.evidenceDigest, /^[a-f0-9]{64}$/);
  assert.equal(payload.record.qualifiedRail.state, "NOT_ISSUED");
  assert.equal(payload.record.chainRail.state, "NOT_ANCHORED");
  assert.equal(payload.record.storage.state, "STORED_ENCRYPTED");
  assert.equal(payload.operationalAudit.state, "RECORDED");
  assert.equal(payload.operationalAudit.role, "APPLICATION_AUDIT_ONLY");
  assert.equal(payload.operationalAudit.independentlyAnchored, false);
  assert.equal(payload.operationalAudit.eventHashValid, true);
  assert.match(payload.record.receiptSha256, /^[a-f0-9]{64}$/);
  assert.equal(payload.storage.persistent, false);
  assert.deepEqual(payload.storage.database, {
    mode: "memory",
    persistent: false,
  });
  assert.deepEqual(payload.storage.objects, {
    mode: "memory",
    persistent: false,
    state: "STORED_ENCRYPTED",
    plaintextReceived: false,
  });
  assert.deepEqual(payload.storage.audit, {
    mode: "memory",
    persistent: false,
    appendOnly: true,
    hashChained: true,
    independentlyAnchored: false,
  });
  assert.deepEqual(payload.coordination, {
    mode: "memory",
    distributed: false,
    authoritative: false,
  });
  assert.equal(JSON.stringify(payload).includes("originalBase64"), false);
  assert.equal(
    JSON.stringify(payload).includes(upload.recoveryTokenSha256),
    false,
  );
});

test("submission IDs make client retries idempotent", async () => {
  const body = validRequest();
  const first = await createReceipt(body);
  const second = await createReceipt(body);
  assert.equal(first.response.status, 201);
  assert.equal(second.response.status, 200);
  assert.equal(second.payload.created, false);
  assert.equal(second.payload.status, "IDEMPOTENT_RECEIPT_REUSED");
  assert.equal(second.payload.record.recordId, first.payload.record.recordId);
});

test("a created receipt is publicly retrievable with pending rails", async () => {
  const created = await createReceipt();
  const response = await fetch(
    `${baseUrl}/api/verify/${encodeURIComponent(created.payload.record.recordId)}`,
  );
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.status, "EXTERNAL_PROOFS_PENDING");
  assert.equal(payload.proofsComplete, false);
  assert.equal(payload.record.sha256, created.payload.record.sha256);
  assert.equal(payload.operationalAudit.state, "RECORDED");
  assert.equal(payload.operationalAudit.eventHashValid, true);
  assert.match(payload.scope.doesNotProve, /qualified eIDAS timestamp/);
});

test("public bundle binds both encrypted manifest and encrypted-original digest", async () => {
  const created = await createReceipt();
  const response = await fetch(
    `${baseUrl}/api/records/${encodeURIComponent(created.payload.record.recordId)}/bundle`,
  );
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-disposition"), /proof-bundle\.json/);
  const payload = await response.json();
  assert.equal(payload.schemaVersion, "sitesealed.proof-bundle.v1.4-alpha.1");
  assert.equal(payload.bundleVersion, "1.4-alpha.1");
  assert.equal(payload.receiptSha256, created.payload.record.receiptSha256);
  assert.equal(payload.encryptedManifest.algorithm, "AES-256-GCM");
  assert.equal(payload.encryptedOriginal.state, "STORED_ENCRYPTED");
  assert.match(payload.encryptedOriginal.ciphertextSha256, /^[a-f0-9]{64}$/);
  assert.equal(Object.hasOwn(payload.encryptedOriginal, "objectKey"), false);
  assert.equal(JSON.stringify(payload).includes("recoveryTokenSha256"), false);
  assert.equal(Object.hasOwn(payload, "original"), false);
  assert.equal(payload.operationalAudit.state, "RECORDED");
  assert.equal(payload.operationalAudit.eventHashValid, true);
  assert.equal(payload.operationalAudit.independentlyAnchored, false);
});

test("the encrypted original requires the private recovery token and retains integrity", async () => {
  const created = await createReceipt();
  const url =
    `${baseUrl}/api/records/` +
    `${encodeURIComponent(created.payload.record.recordId)}/encrypted-original`;

  const rejected = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ recoveryToken: Buffer.alloc(32, 99).toString("base64") }),
  });
  assert.equal(rejected.status, 403);

  const accepted = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      recoveryToken: created.upload.recoveryToken.toString("base64"),
    }),
  });
  assert.equal(accepted.status, 200);
  assert.match(
    accepted.headers.get("content-type"),
    /application\/vnd\.sitesealed\.encrypted-original/,
  );
  assert.equal(
    accepted.headers.get("x-sitesealed-cipher-sha256"),
    sha256(created.upload.ciphertext),
  );
  assert.deepEqual(
    Buffer.from(await accepted.arrayBuffer()),
    created.upload.ciphertext,
  );
});

test("each real receipt has a dynamic one-page PDF endpoint", async () => {
  const created = await createReceipt();
  const response = await fetch(
    `${baseUrl}/api/records/${encodeURIComponent(created.payload.record.recordId)}/report.pdf`,
  );
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /application\/pdf/);
  assert.match(response.headers.get("content-disposition"), /alpha-receipt\.pdf/);
  const bytes = Buffer.from(await response.arrayBuffer());
  assert.equal(bytes.subarray(0, 5).toString("ascii"), "%PDF-");
  assert.ok(bytes.length > 2_000);
});

test("requests that try to include original file data are rejected", async () => {
  const body = validRequest({ originalBase64: "do-not-accept" });
  const response = await fetch(`${baseUrl}/api/records`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  assert.equal(response.status, 400);
  const payload = await response.json();
  assert.equal(payload.code, "UNEXPECTED_FIELD");
  assert.match(payload.message, /must never be sent/);
});

test("specimen verification remains available and explicitly simulated", async () => {
  const response = await fetch(`${baseUrl}/api/verify/sr-2026-08-0147-a3`);
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.specimen, true);
  assert.equal(payload.status, "SPECIMEN_RECORD_FOUND");
  assert.equal(payload.record.qualifiedRail.state, "SIMULATED");
  assert.equal(payload.proofsComplete, false);
});

test("unknown records fail honestly", async () => {
  const response = await fetch(`${baseUrl}/api/verify/SR-20260811-AAAAAAAAAAAAAAAAAAAAAAAA`);
  assert.equal(response.status, 404);
  const payload = await response.json();
  assert.equal(payload.ok, false);
  assert.equal(payload.code, "RECORD_NOT_FOUND");
});

test("the production server serves the React application, official brand assets and v1.4 proof documents", async () => {
  const [homeResponse, faviconResponse, iconResponse, icon512Response, manifestResponse, reportResponse, schemaResponse] = await Promise.all([
    fetch(`${baseUrl}/`),
    fetch(`${baseUrl}/favicon.svg?v=20260812`),
    fetch(`${baseUrl}/icon-192.svg`),
    fetch(`${baseUrl}/icon-512.svg?v=20260812`),
    fetch(`${baseUrl}/site.webmanifest`),
    fetch(`${baseUrl}/documents/SiteSealed_EvidenceReport_SPECIMEN.pdf`),
    fetch(`${baseUrl}/schemas/proof-bundle-v1.4-alpha.1.schema.json`),
  ]);
  assert.equal(homeResponse.status, 200);
  const homeHtml = await homeResponse.text();
  assert.match(homeHtml, /id="root"/);
  assert.match(homeHtml, /favicon\.svg\?v=20260812/);
  assert.equal(faviconResponse.status, 200);
  assert.match(faviconResponse.headers.get("content-type"), /image\/svg\+xml/);
  assert.match(faviconResponse.headers.get("cache-control"), /no-cache/);
  assert.equal(iconResponse.status, 200);
  assert.match(iconResponse.headers.get("content-type"), /image\/svg\+xml/);
  assert.match(iconResponse.headers.get("cache-control"), /no-cache/);
  assert.equal(icon512Response.status, 200);
  assert.match(icon512Response.headers.get("content-type"), /image\/svg\+xml/);
  assert.match(icon512Response.headers.get("cache-control"), /no-cache/);
  assert.equal(manifestResponse.status, 200);
  assert.match(manifestResponse.headers.get("content-type"), /manifest\+json|application\/json/);
  assert.match(manifestResponse.headers.get("cache-control"), /no-cache/);
  assert.equal(reportResponse.status, 200);
  assert.match(reportResponse.headers.get("content-type"), /application\/pdf/);
  assert.equal(schemaResponse.status, 200);
});

test("malformed JSON receives a controlled client error", async () => {
  const response = await fetch(`${baseUrl}/api/records`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{not-json}",
  });
  assert.equal(response.status, 400);
  const payload = await response.json();
  assert.equal(payload.code, "INVALID_JSON");
});

test("the anonymous sealing limiter returns standard retry guidance", async () => {
  const limitedApp = createApp({
    recordStore: createMemoryRecordStore(),
    sealRateLimit: 1,
  });
  const limitedServer = await new Promise((resolve) => {
    const instance = limitedApp.listen(0, "127.0.0.1", () => resolve(instance));
  });
  const address = limitedServer.address();
  const limitedBaseUrl = `http://127.0.0.1:${address.port}`;

  try {
    const upload = async (body) => {
      const fixture = body[TEST_UPLOAD];
      return fetch(
        `${limitedBaseUrl}/api/storage/uploads/${encodeURIComponent(body.submissionId)}`,
        {
          method: "PUT",
          headers: {
            "content-type": "application/octet-stream",
            "x-sitesealed-record-sha256": body.recordSha256,
            "x-sitesealed-cipher-sha256": sha256(fixture.ciphertext),
            "x-sitesealed-cipher-iv": fixture.iv,
            "x-sitesealed-original-bytes": String(fixture.plaintextBytes),
            "x-sitesealed-recovery-token-sha256":
              fixture.recoveryTokenSha256,
          },
          body: fixture.ciphertext,
        },
      );
    };
    const first = await upload(validRequest());
    const second = await upload(validRequest());
    assert.equal(first.status, 201);
    assert.equal(second.status, 429);
    assert.ok(Number(second.headers.get("retry-after")) > 0);
  } finally {
    await new Promise((resolve, reject) =>
      limitedServer.close((error) => (error ? reject(error) : resolve())),
    );
  }
});
