import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { after, before, test } from "node:test";
import { resolveUploadAdmissionConfig } from "./admission.js";
import { createMemoryCoordinator } from "./coordination.js";
import { createApp } from "./server.js";
import { createMemoryRecordStore } from "./specimen.js";
import { createMemoryObjectStore } from "./storage.js";

let server;
let baseUrl;
let testCoordinator;
let testAuth;
let sequence = 0;
const TEST_UPLOAD = Symbol("testUpload");
const TEST_GRANT = Symbol("testGrant");
const TEST_UPLOAD_ADMISSION = resolveUploadAdmissionConfig({
  DATABASE_MODE: "required",
});
const TEST_USER = {
  id: "a".repeat(64),
  provider: "GOOGLE",
  email: "alpha9@example.test",
  name: "Alpha Nine",
};
const TEST_OTHER_USER = {
  id: "b".repeat(64),
  provider: "GOOGLE",
  email: "other@example.test",
  name: "Other Account",
};
const TEST_IDENTITY_SERVICE = {
  mode: "google_oidc",
  configured: true,
  secureCookies: false,
  sessionTtlMs: 7 * 24 * 60 * 60 * 1000,
  publicConfig() {
    return {
      provider: "GOOGLE",
      configured: true,
      clientId: "123456789-alpha9.apps.googleusercontent.com",
      loginUri: "http://localhost/api/auth/google/callback",
      configurationError: null,
    };
  },
  async verifyCredential() {
    return TEST_USER;
  },
  async healthCheck() {
    return {
      mode: "google_oidc",
      status: "configured",
      configured: true,
      sessionStore: "REDIS",
      requestedIdentityClaims: ["openid", "email", "profile"],
      googleApiAccess: false,
      configurationError: null,
    };
  },
};

function sessionHeaders(session, { csrf = true } = {}) {
  return {
    cookie: `sitesealed_session=${session.token}`,
    ...(csrf ? { "x-sitesealed-csrf": session.csrfToken } : {}),
  };
}

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

function uploadBindingFor(body) {
  const upload = body[TEST_UPLOAD];
  return {
    submissionId: body.submissionId,
    recordSha256: body.recordSha256,
    ciphertextSha256: sha256(upload.ciphertext),
    ciphertextBytes: upload.ciphertext.length,
    plaintextBytes: upload.plaintextBytes,
    iv: upload.iv,
    recoveryTokenSha256: upload.recoveryTokenSha256,
  };
}

function uploadHeadersFor(body, grant, auth = testAuth) {
  const upload = body[TEST_UPLOAD];
  return {
    "content-type": "application/octet-stream",
    "x-sitesealed-record-sha256": body.recordSha256,
    "x-sitesealed-cipher-sha256": sha256(upload.ciphertext),
    "x-sitesealed-cipher-iv": upload.iv,
    "x-sitesealed-original-bytes": String(upload.plaintextBytes),
    "x-sitesealed-recovery-token-sha256": upload.recoveryTokenSha256,
    "x-sitesealed-upload-grant": grant,
    ...(auth?.cookie ? { cookie: auth.cookie } : {}),
  };
}

async function issueUploadGrant(url, body, auth = testAuth) {
  const response = await fetch(`${url}/api/storage/upload-grants`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(auth ?? {}),
    },
    body: JSON.stringify(uploadBindingFor(body)),
  });
  return { response, payload: await response.json() };
}

async function listen(app) {
  const instance = await new Promise((resolve) => {
    const candidate = app.listen(0, "127.0.0.1", () => resolve(candidate));
  });
  return {
    server: instance,
    url: `http://127.0.0.1:${instance.address().port}`,
  };
}

async function close(instance) {
  await new Promise((resolve, reject) =>
    instance.close((error) => (error ? reject(error) : resolve())),
  );
}

async function listenAuthenticated(options = {}) {
  const coordinator = options.coordinator ?? createMemoryCoordinator();
  const session = await coordinator.createAuthSession(TEST_USER, {
    ttlMs: TEST_IDENTITY_SERVICE.sessionTtlMs,
  });
  const listened = await listen(
    createApp({
      ...options,
      coordinator,
      identityService: TEST_IDENTITY_SERVICE,
    }),
  );
  return {
    ...listened,
    coordinator,
    auth: sessionHeaders(session),
  };
}

async function createReceipt(body = validRequest()) {
  const upload = body[TEST_UPLOAD];
  if (!body.encryptedObject) {
    const binding = {
      submissionId: body.submissionId,
      recordSha256: body.recordSha256,
      ciphertextSha256: sha256(upload.ciphertext),
      ciphertextBytes: upload.ciphertext.length,
      plaintextBytes: upload.plaintextBytes,
      iv: upload.iv,
      recoveryTokenSha256: upload.recoveryTokenSha256,
    };
    const grantResponse = await fetch(`${baseUrl}/api/storage/upload-grants`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...testAuth,
      },
      body: JSON.stringify(binding),
    });
    const grantPayload = await grantResponse.json();
    assert.ok(grantResponse.ok, JSON.stringify(grantPayload));
    body[TEST_GRANT] = grantPayload.grant;
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
          "x-sitesealed-upload-grant": grantPayload.grant,
          cookie: testAuth.cookie,
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
    headers: {
      "content-type": "application/json",
      "x-sitesealed-upload-grant": body[TEST_GRANT],
      ...testAuth,
    },
    body: JSON.stringify(body),
  });
  return { response, payload: await response.json(), body, upload };
}

before(async () => {
  testCoordinator = createMemoryCoordinator();
  const session = await testCoordinator.createAuthSession(TEST_USER, {
    ttlMs: TEST_IDENTITY_SERVICE.sessionTtlMs,
  });
  testAuth = sessionHeaders(session);
  const app = createApp({
    recordStore: createMemoryRecordStore(),
    coordinator: testCoordinator,
    identityService: TEST_IDENTITY_SERVICE,
    sealRateLimit: 100,
    uploadAdmission: TEST_UPLOAD_ADMISSION,
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

test("health endpoint reports the honest v1.5-alpha.1 capability boundary", async () => {
  const response = await fetch(`${baseUrl}/api/health`);
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.ok, true);
  assert.equal(payload.service, "sitesealed");
  assert.equal(payload.version, "1.5.0-alpha.1");
  assert.equal(
    payload.sealing.workflow,
    "CONTEXT_BOUND_WEB_CAPTURE_WITH_SEPARATE_IMPORTED_CLASS",
  );
  assert.deepEqual(payload.sealing.liveCapture, {
    officialUiUsesCameraOnly: true,
    freshServerChallenge: true,
    browserGeolocationManifestBound: true,
    accountBound: true,
    hardwareDeviceAttestation: false,
    browserGeolocationHardwareAttested: false,
    physicalSensorOriginProven: false,
    directApiClientExcluded: false,
    offlineQueue: false,
  });
  assert.equal(payload.sealing.clientEncryptedObjectStorage, true);
  assert.equal(
    payload.sealing.operationalAudit,
    "POSTGRESQL_APPEND_ONLY_HASH_CHAIN",
  );
  assert.equal(payload.sealing.distributedCoordination, true);
  assert.equal(payload.sealing.qualifiedTimestamp, false);
  assert.equal(payload.sealing.publicChainAnchor, false);
  assert.equal(payload.sealing.finalSealedStatusEnabled, false);
  assert.deepEqual(payload.sealing.uploadAdmission, {
    mode: "GOOGLE_ACCOUNT_SESSION",
    configured: true,
    oneTimeGrants: true,
    accountBound: true,
    preBodyClaim: true,
    dailyLimitMiB: 2048,
    perUserDailyLimitMiB: 256,
  });
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
    stagedUploadPrefix: "staging/v1.2/",
    orphanCleanup: "APPLICATION_WORKER",
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
    uploadGrants: true,
    captureChallenges: true,
    accountSessions: true,
    boundedStorageAdmission: true,
    verificationCache: true,
    runtimeRailStatus: true,
  });
  assert.deepEqual(payload.authentication, {
    mode: "google_oidc",
    status: "configured",
    configured: true,
    sessionStore: "MEMORY",
    requestedIdentityClaims: ["openid", "email", "profile"],
    googleApiAccess: false,
    configurationError: null,
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

test("Google sign-in creates an HttpOnly SiteSealed session after the double-submit CSRF check", async () => {
  const configResponse = await fetch(`${baseUrl}/api/auth/config`);
  const config = await configResponse.json();
  assert.equal(configResponse.status, 200);
  assert.equal(config.configured, true);
  assert.equal(config.provider, "GOOGLE");

  const rejected = await fetch(`${baseUrl}/api/auth/google/callback`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: "g_csrf_token=cookie-token",
    },
    body: new URLSearchParams({
      credential: "header.payload.signature",
      g_csrf_token: "different-token",
    }),
    redirect: "manual",
  });
  assert.equal(rejected.status, 400);
  assert.equal((await rejected.json()).code, "GOOGLE_CSRF_REJECTED");

  const accepted = await fetch(`${baseUrl}/api/auth/google/callback`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: "g_csrf_token=matching-token",
    },
    body: new URLSearchParams({
      credential: "header.payload.signature",
      g_csrf_token: "matching-token",
    }),
    redirect: "manual",
  });
  assert.equal(accepted.status, 303);
  assert.equal(accepted.headers.get("location"), "/#seal");
  assert.match(
    accepted.headers.get("set-cookie"),
    /sitesealed_session=.*HttpOnly.*SameSite=Lax/i,
  );
});

test("authenticated mutations reject a missing application CSRF token", async () => {
  const body = validRequest();
  const response = await issueUploadGrant(baseUrl, body, {
    cookie: testAuth.cookie,
  });
  assert.equal(response.response.status, 403);
  assert.equal(response.payload.code, "CSRF_REJECTED");
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

test("health exposes Ethereum FINALIZED only with binding and finality evidence", async () => {
  const coordinator = createMemoryCoordinator();
  await coordinator.setRailRuntimeStatus("ethereum", {
    mode: "ethereum",
    status: "finalized",
    network: "Ethereum mainnet",
    chainId: 1,
    configured: true,
    writesEnabled: true,
    dryRun: false,
    anchorAddress: `0x${"1".repeat(40)}`,
    transactionHash: `0x${"2".repeat(64)}`,
    onChainBindingVerified: true,
    finalityVerified: true,
    lastCheckedAt: "2026-08-12T21:00:00.000Z",
    lastFinalizedAt: "2026-08-12T20:59:00.000Z",
  });
  const statusApp = createApp({
    recordStore: createMemoryRecordStore(),
    coordinator,
    sealRateLimit: 100,
  });
  const statusServer = await new Promise((resolve) => {
    const instance = statusApp.listen(0, "127.0.0.1", () => resolve(instance));
  });
  try {
    const address = statusServer.address();
    const response = await fetch(`http://127.0.0.1:${address.port}/api/health`);
    const payload = await response.json();
    assert.equal(payload.publicChainAnchor.status, "finalized");
    assert.equal(payload.publicChainAnchor.finalityVerified, true);
    assert.equal(payload.sealing.publicChainAnchor, "ETHEREUM_MAINNET_FINALIZED");
  } finally {
    await new Promise((resolve, reject) =>
      statusServer.close((error) => (error ? reject(error) : resolve())),
    );
  }
});

test("health downgrades an unsupported Ethereum finalized claim", async () => {
  const coordinator = createMemoryCoordinator();
  await coordinator.setRailRuntimeStatus("ethereum", {
    mode: "ethereum",
    status: "finalized",
    network: "Ethereum mainnet",
    chainId: 1,
    configured: true,
    anchorAddress: `0x${"3".repeat(40)}`,
    transactionHash: `0x${"4".repeat(64)}`,
    onChainBindingVerified: true,
    finalityVerified: false,
    lastFinalizedAt: "2026-08-12T20:59:00.000Z",
  });
  const statusApp = createApp({
    recordStore: createMemoryRecordStore(),
    coordinator,
    sealRateLimit: 100,
  });
  const statusServer = await new Promise((resolve) => {
    const instance = statusApp.listen(0, "127.0.0.1", () => resolve(instance));
  });
  try {
    const address = statusServer.address();
    const response = await fetch(`http://127.0.0.1:${address.port}/api/health`);
    const payload = await response.json();
    assert.equal(payload.publicChainAnchor.status, "configured");
    assert.equal(payload.publicChainAnchor.finalityVerified, false);
    assert.equal(payload.sealing.publicChainAnchor, "ETHEREUM_MAINNET_READY");
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

test("capture challenges require both the authenticated account and application CSRF", async () => {
  const submissionId = "123e4567-e89b-42d3-a456-426614174777";
  const unauthenticated = await fetch(`${baseUrl}/api/capture/challenges`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ submissionId }),
  });
  assert.equal(unauthenticated.status, 401);

  const noCsrf = await fetch(`${baseUrl}/api/capture/challenges`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: testAuth.cookie,
    },
    body: JSON.stringify({ submissionId }),
  });
  assert.equal(noCsrf.status, 403);

  const extraField = await fetch(`${baseUrl}/api/capture/challenges`, {
    method: "POST",
    headers: { "content-type": "application/json", ...testAuth },
    body: JSON.stringify({ submissionId, recordSha256: "a".repeat(64) }),
  });
  assert.equal(extraField.status, 400);
  assert.equal(
    (await extraField.json()).code,
    "INVALID_CAPTURE_CHALLENGE_REQUEST",
  );
});

test("a live web capture requires and consumes a fresh account-bound challenge", async () => {
  const body = validRequest({ recordClass: "LIVE_CAPTURE_WEB" });
  const challengeResponse = await fetch(`${baseUrl}/api/capture/challenges`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...testAuth,
    },
    body: JSON.stringify({ submissionId: body.submissionId }),
  });
  const challenge = await challengeResponse.json();
  assert.equal(challengeResponse.status, 201);
  assert.equal(challenge.status, "CAPTURE_CHALLENGE_ISSUED");
  assert.equal(challenge.timeAuthority, "SITESEALED_SERVER_CHALLENGE");

  const capturedAt = new Date(
    Date.parse(challenge.issuedAt) + 10_000,
  ).toISOString();
  body.captureProof = {
    challenge: challenge.challenge,
    capturedAt,
    locationMeasuredAt: capturedAt,
    locationAccuracyMeters: 7.4,
    clockDeltaMs: 12,
    cameraFacingMode: "environment",
    deviceAttestation: "NOT_AVAILABLE_WEB_ALPHA",
    locationAttestation: "BROWSER_GEOLOCATION_NOT_HARDWARE_ATTESTED",
    timeAttestation: "SERVER_CHALLENGE_WINDOW",
    coordinatesManifestBound: true,
  };

  const created = await createReceipt(body);
  assert.equal(created.response.status, 201);
  assert.equal(created.payload.record.recordClass, "LIVE_CAPTURE_WEB");
  assert.equal(
    created.payload.record.classification,
    "Context-bound web camera capture - alpha",
  );
  assert.equal(created.payload.record.capturedAt, capturedAt);
  assert.equal(
    created.payload.record.captureContext.challengeId,
    challenge.challengeId,
  );
  assert.equal(
    created.payload.record.captureContext.account.provider,
    "GOOGLE",
  );
  assert.match(
    created.payload.record.captureContext.account.accountReference,
    /^[a-f0-9]{64}$/,
  );
  assert.equal(
    created.payload.record.captureContext.deviceAttestation,
    "NOT_AVAILABLE_WEB_ALPHA",
  );
  assert.equal(
    Object.hasOwn(created.payload.record.captureContext.location, "latitude"),
    false,
  );
  assert.equal(
    Object.hasOwn(created.payload.record.captureContext.location, "longitude"),
    false,
  );
  assert.equal(
    JSON.stringify(created.payload).includes(challenge.challenge),
    false,
  );
  assert.match(created.payload.scope.attests, /fresh, submission-bound/);
  assert.match(created.payload.scope.doesNotProve, /virtual camera/);

  const replay = await createReceipt(body);
  assert.equal(replay.response.status, 200);
  assert.equal(replay.payload.record.recordId, created.payload.record.recordId);
});

test("an imported or pre-existing file cannot self-assert the live-capture class", async () => {
  const body = validRequest({
    recordClass: "LIVE_CAPTURE_WEB",
    captureProof: {
      challenge: `123e4567-e89b-42d3-a456-426614174000.${"A".repeat(43)}`,
      capturedAt: new Date().toISOString(),
      locationMeasuredAt: new Date().toISOString(),
      locationAccuracyMeters: 10,
      clockDeltaMs: 0,
      cameraFacingMode: "unknown",
      deviceAttestation: "NOT_AVAILABLE_WEB_ALPHA",
      locationAttestation: "BROWSER_GEOLOCATION_NOT_HARDWARE_ATTESTED",
      timeAttestation: "SERVER_CHALLENGE_WINDOW",
      coordinatesManifestBound: true,
    },
  });
  const rejected = await createReceipt(body);
  assert.equal(rejected.response.status, 403);
  assert.equal(rejected.payload.code, "CAPTURE_CHALLENGE_REJECTED");
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
  assert.equal(payload.schemaVersion, "sitesealed.proof-bundle.v1.5-alpha.1");
  assert.equal(payload.bundleVersion, "1.5-alpha.1");
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

test("the server does not manufacture an Evidence Report without the exact original", async () => {
  const created = await createReceipt();
  const response = await fetch(
    `${baseUrl}/api/records/${encodeURIComponent(created.payload.record.recordId)}/report.pdf`,
  );
  assert.equal(response.status, 404);
  assert.equal(Object.hasOwn(created.payload.links, "receiptPdf"), false);
});

test("requests that try to include original file data are rejected", async () => {
  const body = validRequest({ originalBase64: "do-not-accept" });
  const response = await fetch(`${baseUrl}/api/records`, {
    method: "POST",
    headers: { "content-type": "application/json", ...testAuth },
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

test("the production server serves the React application, official brand assets and compatible proof schemas", async () => {
  const [homeResponse, faviconResponse, iconResponse, icon512Response, manifestResponse, reportResponse, legacySchemaResponse, currentSchemaResponse] = await Promise.all([
    fetch(`${baseUrl}/`),
    fetch(`${baseUrl}/favicon.svg?v=20260812`),
    fetch(`${baseUrl}/icon-192.svg`),
    fetch(`${baseUrl}/icon-512.svg?v=20260812`),
    fetch(`${baseUrl}/site.webmanifest`),
    fetch(`${baseUrl}/documents/SiteSealed_EvidenceReport_SPECIMEN.pdf`),
    fetch(`${baseUrl}/schemas/proof-bundle-v1.4-alpha.1.schema.json`),
    fetch(`${baseUrl}/schemas/proof-bundle-v1.5-alpha.1.schema.json`),
  ]);
  assert.equal(homeResponse.status, 200);
  const homeHtml = await homeResponse.text();
  assert.match(homeHtml, /id="root"/);
  assert.match(homeHtml, /favicon\.svg\?v=20260812/);
  assert.match(homeHtml, /<html lang="en-US">/);
  const cspNonce = homeHtml.match(
    /name="sitesealed-csp-nonce" content="([A-Za-z0-9_-]+)"/,
  )?.[1];
  assert.ok(cspNonce);
  assert.ok(cspNonce.length >= 24);
  assert.doesNotMatch(homeHtml, /__SITESEALED_CSP_NONCE__/);
  assert.equal(homeResponse.headers.get("content-language"), "en-US");
  const contentSecurityPolicy =
    homeResponse.headers.get("content-security-policy") ?? "";
  assert.match(
    contentSecurityPolicy,
    new RegExp(`script-src[^;]*'nonce-${cspNonce}'`),
  );
  assert.match(
    contentSecurityPolicy,
    new RegExp(`style-src[^;]*'nonce-${cspNonce}'`),
  );
  assert.doesNotMatch(contentSecurityPolicy, /unsafe-inline/);
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
  assert.equal(legacySchemaResponse.status, 200);
  assert.equal(currentSchemaResponse.status, 200);
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

test("the controlled-alpha grant limiter returns standard retry guidance", async () => {
  const limited = await listenAuthenticated({
    recordStore: createMemoryRecordStore(),
    sealRateLimit: 1,
    uploadAdmission: TEST_UPLOAD_ADMISSION,
  });

  try {
    const issueGrant = async (body) => {
      const fixture = body[TEST_UPLOAD];
      return fetch(`${limited.url}/api/storage/upload-grants`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...limited.auth,
        },
        body: JSON.stringify({
          submissionId: body.submissionId,
          recordSha256: body.recordSha256,
          ciphertextSha256: sha256(fixture.ciphertext),
          ciphertextBytes: fixture.ciphertext.length,
          plaintextBytes: fixture.plaintextBytes,
          iv: fixture.iv,
          recoveryTokenSha256: fixture.recoveryTokenSha256,
        }),
      });
    };
    const first = await issueGrant(validRequest());
    const second = await issueGrant(validRequest());
    assert.equal(first.status, 201);
    assert.equal(second.status, 429);
    assert.ok(Number(second.headers.get("retry-after")) > 0);
  } finally {
    await close(limited.server);
  }
});

test("storage grants require an authenticated account and remain account-bound", async () => {
  const body = validRequest();
  const rejected = await issueUploadGrant(baseUrl, body, null);
  assert.equal(rejected.response.status, 401);
  assert.equal(rejected.payload.code, "AUTHENTICATION_REQUIRED");

  const accepted = await issueUploadGrant(baseUrl, body);
  assert.equal(accepted.response.status, 201);
  assert.equal(accepted.payload.status, "UPLOAD_GRANT_ISSUED");
  assert.match(
    accepted.payload.grant,
    /^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/,
  );

  const otherSession = await testCoordinator.createAuthSession(TEST_OTHER_USER, {
    ttlMs: TEST_IDENTITY_SERVICE.sessionTtlMs,
  });
  const otherAuth = sessionHeaders(otherSession);
  const stolen = await fetch(
    `${baseUrl}/api/storage/uploads/${encodeURIComponent(body.submissionId)}`,
    {
      method: "PUT",
      headers: uploadHeadersFor(body, accepted.payload.grant, otherAuth),
      body: body[TEST_UPLOAD].ciphertext,
    },
  );
  assert.equal(stolen.status, 403);
  assert.equal((await stolen.json()).code, "UPLOAD_GRANT_REJECTED");
});

test("receipt creation requires the same completed upload grant", async () => {
  const body = validRequest();
  const issued = await issueUploadGrant(baseUrl, body);
  const uploadResponse = await fetch(
    `${baseUrl}/api/storage/uploads/${encodeURIComponent(body.submissionId)}`,
    {
      method: "PUT",
      headers: uploadHeadersFor(body, issued.payload.grant),
      body: body[TEST_UPLOAD].ciphertext,
    },
  );
  const uploaded = await uploadResponse.json();
  assert.equal(uploadResponse.status, 201);
  body.encryptedObject = uploaded.encryptedObject;

  const rejected = await fetch(`${baseUrl}/api/records`, {
    method: "POST",
    headers: { "content-type": "application/json", ...testAuth },
    body: JSON.stringify(body),
  });
  assert.equal(rejected.status, 403);
  assert.equal(
    (await rejected.json()).code,
    "COMPLETED_UPLOAD_GRANT_REQUIRED",
  );

  const accepted = await fetch(`${baseUrl}/api/records`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-sitesealed-upload-grant": issued.payload.grant,
      ...testAuth,
    },
    body: JSON.stringify(body),
  });
  assert.equal(accepted.status, 201);
});

test("receipt creation accepts a completed Redis descriptor with reordered JSON fields", async () => {
  const coordinator = createMemoryCoordinator();
  const claimUploadGrant = coordinator.claimUploadGrant.bind(coordinator);
  coordinator.claimUploadGrant = async (...arguments_) => {
    const claim = await claimUploadGrant(...arguments_);
    if (claim.state !== "completed") return claim;
    return {
      ...claim,
      descriptor: Object.fromEntries(
        Object.entries(claim.descriptor).reverse(),
      ),
    };
  };
  const isolated = await listenAuthenticated({
    coordinator,
    recordStore: createMemoryRecordStore(),
    objectStore: createMemoryObjectStore(),
    sealRateLimit: 100,
    uploadAdmission: TEST_UPLOAD_ADMISSION,
  });
  try {
    const body = validRequest();
    const issued = await issueUploadGrant(isolated.url, body, isolated.auth);
    assert.equal(issued.response.status, 201);
    const uploadResponse = await fetch(
      `${isolated.url}/api/storage/uploads/${encodeURIComponent(body.submissionId)}`,
      {
        method: "PUT",
        headers: uploadHeadersFor(body, issued.payload.grant, isolated.auth),
        body: body[TEST_UPLOAD].ciphertext,
      },
    );
    const uploaded = await uploadResponse.json();
    assert.equal(uploadResponse.status, 201);
    body.encryptedObject = uploaded.encryptedObject;

    const recordResponse = await fetch(`${isolated.url}/api/records`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-sitesealed-upload-grant": issued.payload.grant,
        ...isolated.auth,
      },
      body: JSON.stringify(body),
    });
    assert.equal(recordResponse.status, 201, await recordResponse.text());
  } finally {
    await close(isolated.server);
  }
});

test("a forged grant is rejected before encrypted bytes reach object storage", async () => {
  const objectStore = createMemoryObjectStore();
  let storageCalls = 0;
  const originalPut = objectStore.putStagedEncryptedOriginal.bind(objectStore);
  objectStore.putStagedEncryptedOriginal = async (...args) => {
    storageCalls += 1;
    return originalPut(...args);
  };
  const isolated = await listenAuthenticated({
    recordStore: createMemoryRecordStore(),
    objectStore,
    sealRateLimit: 100,
    uploadAdmission: TEST_UPLOAD_ADMISSION,
  });
  const body = validRequest();
  try {
    const response = await fetch(
      `${isolated.url}/api/storage/uploads/${encodeURIComponent(body.submissionId)}`,
      {
        method: "PUT",
        headers: uploadHeadersFor(
          body,
          `123e4567-e89b-42d3-a456-426614174000.${"A".repeat(43)}`,
          isolated.auth,
        ),
        body: body[TEST_UPLOAD].ciphertext,
      },
    );
    assert.equal(response.status, 403);
    assert.equal((await response.json()).code, "UPLOAD_GRANT_REJECTED");
    assert.equal(storageCalls, 0);
  } finally {
    await close(isolated.server);
  }
});

test("a one-time grant permits only one concurrent object-store write", async () => {
  const objectStore = createMemoryObjectStore();
  const originalPut = objectStore.putStagedEncryptedOriginal.bind(objectStore);
  let storageCalls = 0;
  let announceStarted;
  let allowStorage;
  const started = new Promise((resolve) => {
    announceStarted = resolve;
  });
  const gate = new Promise((resolve) => {
    allowStorage = resolve;
  });
  objectStore.putStagedEncryptedOriginal = async (...args) => {
    storageCalls += 1;
    announceStarted();
    await gate;
    return originalPut(...args);
  };
  const isolated = await listenAuthenticated({
    recordStore: createMemoryRecordStore(),
    objectStore,
    sealRateLimit: 100,
    uploadAdmission: TEST_UPLOAD_ADMISSION,
  });
  const body = validRequest();
  try {
    const issued = await issueUploadGrant(isolated.url, body, isolated.auth);
    assert.equal(issued.response.status, 201);
    const url = `${isolated.url}/api/storage/uploads/${encodeURIComponent(body.submissionId)}`;
    const options = {
      method: "PUT",
      headers: uploadHeadersFor(body, issued.payload.grant, isolated.auth),
      body: body[TEST_UPLOAD].ciphertext,
    };
    const firstPromise = fetch(url, options);
    await started;
    const concurrent = await fetch(url, options);
    assert.equal(concurrent.status, 409);
    assert.equal((await concurrent.json()).code, "UPLOAD_GRANT_IN_PROGRESS");
    allowStorage();
    const first = await firstPromise;
    assert.equal(first.status, 201);

    const replay = await fetch(url, options);
    assert.equal(replay.status, 200);
    assert.equal((await replay.json()).status, "ENCRYPTED_ORIGINAL_REUSED");
    assert.equal(storageCalls, 1);
  } finally {
    allowStorage();
    await close(isolated.server);
  }
});

test("an object-store failure releases the exact grant for a safe retry", async () => {
  const objectStore = createMemoryObjectStore();
  const originalPut = objectStore.putStagedEncryptedOriginal.bind(objectStore);
  let attempts = 0;
  objectStore.putStagedEncryptedOriginal = async (...args) => {
    attempts += 1;
    if (attempts === 1) throw new Error("simulated object-store outage");
    return originalPut(...args);
  };
  const isolated = await listenAuthenticated({
    recordStore: createMemoryRecordStore(),
    objectStore,
    sealRateLimit: 100,
    uploadAdmission: TEST_UPLOAD_ADMISSION,
  });
  const body = validRequest();
  try {
    const issued = await issueUploadGrant(isolated.url, body, isolated.auth);
    const url = `${isolated.url}/api/storage/uploads/${encodeURIComponent(body.submissionId)}`;
    const options = {
      method: "PUT",
      headers: uploadHeadersFor(body, issued.payload.grant, isolated.auth),
      body: body[TEST_UPLOAD].ciphertext,
    };
    assert.equal((await fetch(url, options)).status, 500);
    assert.equal((await fetch(url, options)).status, 201);
    assert.equal(attempts, 2);
  } finally {
    await close(isolated.server);
  }
});
