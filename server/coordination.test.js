import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createMemoryCoordinator,
  resolveRedisConfig,
} from "./coordination.js";

test("Redis configuration accepts Railway REDIS_URL and enforces required mode", () => {
  assert.equal(resolveRedisConfig({ DATABASE_MODE: "optional" }), null);
  assert.throws(
    () => resolveRedisConfig({ DATABASE_MODE: "required" }),
    /REDIS_URL is not configured/,
  );
  const config = resolveRedisConfig({
    DATABASE_MODE: "required",
    REDIS_URL: "redis://default:secret@redis.railway.internal:6379",
  });
  assert.equal(config.verificationCacheTtlMs, 60_000);
  assert.match(config.url, /^redis:\/\//);
  assert.throws(
    () =>
      resolveRedisConfig({
        DATABASE_MODE: "required",
        REDIS_URL: "postgresql://user:secret@host/database",
      }),
    /redis:\/\/ or rediss:\/\//,
  );
});

test("memory coordination enforces a shared window and resets after expiry", async () => {
  let timestamp = 1_000;
  const coordinator = createMemoryCoordinator({ now: () => timestamp });
  const input = {
    scope: "receipt-create",
    identity: "203.0.113.4",
    limit: 2,
    windowMs: 1_000,
  };
  assert.equal((await coordinator.consumeRateLimit(input)).allowed, true);
  assert.equal((await coordinator.consumeRateLimit(input)).remaining, 0);
  assert.equal((await coordinator.consumeRateLimit(input)).allowed, false);
  timestamp = 2_001;
  assert.equal((await coordinator.consumeRateLimit(input)).allowed, true);
});

test("verification cache is transient and returns an isolated copy", async () => {
  let timestamp = 10_000;
  const coordinator = createMemoryCoordinator({ now: () => timestamp });
  const record = { recordId: "SR-1", sha256: "a".repeat(64) };
  await coordinator.setCachedRecord(record.recordId, record, { ttlMs: 500 });
  record.sha256 = "b".repeat(64);
  assert.equal(
    (await coordinator.getCachedRecord(record.recordId)).sha256,
    "a".repeat(64),
  );
  timestamp = 10_501;
  assert.equal(await coordinator.getCachedRecord(record.recordId), null);
});

test("runtime rail status is shared as an isolated expiring snapshot", async () => {
  let timestamp = 15_000;
  const coordinator = createMemoryCoordinator({ now: () => timestamp });
  const status = {
    mode: "evidency",
    status: "operational",
    externalCallVerified: true,
  };
  await coordinator.setRailRuntimeStatus("evidency", status, { ttlMs: 500 });
  status.status = "tampered";
  assert.deepEqual(await coordinator.getRailRuntimeStatus("evidency"), {
    mode: "evidency",
    status: "operational",
    externalCallVerified: true,
  });
  timestamp = 15_501;
  assert.equal(await coordinator.getRailRuntimeStatus("evidency"), null);
});

test("submission locks are exclusive, expiring and safely released", async () => {
  let timestamp = 20_000;
  const coordinator = createMemoryCoordinator({ now: () => timestamp });
  const release = await coordinator.acquireSubmissionLock("submission-a", {
    ttlMs: 1_000,
  });
  assert.equal(typeof release, "function");
  assert.equal(
    await coordinator.acquireSubmissionLock("submission-a", { ttlMs: 1_000 }),
    null,
  );
  await release();
  assert.equal(
    typeof (await coordinator.acquireSubmissionLock("submission-a")),
    "function",
  );

  const expiring = await coordinator.acquireSubmissionLock("submission-b", {
    ttlMs: 500,
  });
  assert.equal(typeof expiring, "function");
  timestamp = 20_501;
  assert.equal(
    typeof (await coordinator.acquireSubmissionLock("submission-b")),
    "function",
  );
});

function uploadBinding(overrides = {}) {
  return {
    submissionId: "123e4567-e89b-42d3-a456-426614174000",
    recordSha256: "a".repeat(64),
    ciphertextSha256: "b".repeat(64),
    ciphertextBytes: 32,
    plaintextBytes: 16,
    iv: Buffer.alloc(12, 3).toString("base64"),
    recoveryTokenSha256: "c".repeat(64),
    ...overrides,
  };
}

const PRINCIPAL_A = "a".repeat(64);
const PRINCIPAL_B = "b".repeat(64);

const admissionOptions = (overrides = {}) => ({
  principalId: PRINCIPAL_A,
  globalBudgetLimitBytes: 64,
  userBudgetLimitBytes: 64,
  ...overrides,
});

test("upload grants are exact-bound, single-claim and replay-safe", async () => {
  const coordinator = createMemoryCoordinator();
  const binding = uploadBinding();
  const issued = await coordinator.issueUploadGrant(binding, {
    ttlMs: 60_000,
    principalId: PRINCIPAL_A,
  });
  assert.match(issued.grant, /^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/);

  const claim = await coordinator.claimUploadGrant(
    issued.grant,
    binding,
    admissionOptions(),
  );
  assert.equal(claim.state, "claimed");
  assert.equal(
    (await coordinator.claimUploadGrant(
      issued.grant,
      binding,
      admissionOptions(),
    )).state,
    "in_progress",
  );
  assert.equal(await claim.release(), true);

  const retry = await coordinator.claimUploadGrant(
    issued.grant,
    binding,
    admissionOptions(),
  );
  assert.equal(retry.state, "claimed");
  const descriptor = { objectKey: "sealed/v1.2/object.ssenc" };
  assert.equal(await retry.complete(descriptor), true);
  const replay = await coordinator.claimUploadGrant(
    issued.grant,
    binding,
    admissionOptions(),
  );
  assert.equal(replay.state, "completed");
  assert.deepEqual(replay.descriptor, descriptor);

  const mismatch = await coordinator.claimUploadGrant(
    issued.grant,
    uploadBinding({ ciphertextSha256: "d".repeat(64) }),
    admissionOptions(),
  );
  assert.equal(mismatch.state, "rejected");
  assert.equal(
    (
      await coordinator.claimUploadGrant(
        issued.grant,
        binding,
        admissionOptions({ principalId: PRINCIPAL_B }),
      )
    ).state,
    "rejected",
  );
});

test("the global storage budget is charged once per claimed grant", async () => {
  const coordinator = createMemoryCoordinator();
  const firstBinding = uploadBinding();
  const secondBinding = uploadBinding({
    submissionId: "223e4567-e89b-42d3-a456-426614174000",
    ciphertextSha256: "d".repeat(64),
  });
  const first = await coordinator.issueUploadGrant(firstBinding, {
    principalId: PRINCIPAL_A,
  });
  const second = await coordinator.issueUploadGrant(secondBinding, {
    principalId: PRINCIPAL_A,
  });
  const firstClaim = await coordinator.claimUploadGrant(
    first.grant,
    firstBinding,
    admissionOptions({ globalBudgetLimitBytes: 32 }),
  );
  assert.equal(firstClaim.state, "claimed");
  await firstClaim.release();
  const retry = await coordinator.claimUploadGrant(
    first.grant,
    firstBinding,
    admissionOptions({ globalBudgetLimitBytes: 32 }),
  );
  assert.equal(retry.state, "claimed");
  const exhausted = await coordinator.claimUploadGrant(
    second.grant,
    secondBinding,
    admissionOptions({ globalBudgetLimitBytes: 32 }),
  );
  assert.equal(exhausted.state, "global_exhausted");
  assert.equal(exhausted.usedBytes, 32);
});

test("expired upload grants fail closed", async () => {
  let timestamp = 1_000;
  const coordinator = createMemoryCoordinator({ now: () => timestamp });
  const binding = uploadBinding();
  const issued = await coordinator.issueUploadGrant(binding, {
    ttlMs: 500,
    principalId: PRINCIPAL_A,
  });
  timestamp = 1_501;
  assert.equal(
    (
      await coordinator.claimUploadGrant(
        issued.grant,
        binding,
        admissionOptions(),
      )
    ).state,
    "rejected",
  );
});

test("an active upload claim cannot be stolen before the grant expires", async () => {
  let timestamp = 1_000;
  const coordinator = createMemoryCoordinator({ now: () => timestamp });
  const binding = uploadBinding();
  const issued = await coordinator.issueUploadGrant(binding, {
    ttlMs: 60_000,
    principalId: PRINCIPAL_A,
  });
  const claim = await coordinator.claimUploadGrant(
    issued.grant,
    binding,
    admissionOptions(),
  );
  assert.equal(claim.state, "claimed");

  timestamp = 31_000;
  assert.equal(
    (
      await coordinator.claimUploadGrant(
        issued.grant,
        binding,
        admissionOptions(),
      )
    ).state,
    "in_progress",
  );
  assert.equal(await claim.release(), true);
});

test("authenticated sessions are opaque, isolated and expiring", async () => {
  let timestamp = 5_000;
  const coordinator = createMemoryCoordinator({ now: () => timestamp });
  const session = await coordinator.createAuthSession(
    {
      id: PRINCIPAL_A,
      provider: "GOOGLE",
      email: "user@example.com",
      name: "Test User",
    },
    { ttlMs: 1_000 },
  );
  assert.match(session.token, /^[A-Za-z0-9_-]{43}$/);
  assert.match(session.csrfToken, /^[A-Za-z0-9_-]{43}$/);
  assert.equal((await coordinator.getAuthSession(session.token)).user.id, PRINCIPAL_A);
  assert.equal(await coordinator.getAuthSession("not-a-token"), null);

  timestamp = 6_001;
  assert.equal(await coordinator.getAuthSession(session.token), null);

  const second = await coordinator.createAuthSession({
    id: PRINCIPAL_B,
    provider: "GOOGLE",
    email: "second@example.com",
    name: "Second User",
  });
  assert.equal(await coordinator.deleteAuthSession(second.token), true);
  assert.equal(await coordinator.getAuthSession(second.token), null);
});

test("capture challenges bind one fresh camera event to one account and submission", async () => {
  let timestamp = Date.parse("2026-08-14T10:00:00.000Z");
  const coordinator = createMemoryCoordinator({ now: () => timestamp });
  const submissionId = "323e4567-e89b-42d3-a456-426614174000";
  const issued = await coordinator.issueCaptureChallenge(submissionId, {
    principalId: PRINCIPAL_A,
    captureWindowMs: 120_000,
    ttlMs: 900_000,
  });
  assert.match(issued.challenge, /^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/);
  assert.equal(issued.timeAuthority, "SITESEALED_SERVER_CHALLENGE");

  const binding = {
    submissionId,
    recordSha256: "d".repeat(64),
    manifestSha256: "e".repeat(64),
    capturedAt: "2026-08-14T10:00:30.000Z",
  };
  const claim = await coordinator.claimCaptureChallenge(
    issued.challenge,
    binding,
    { principalId: PRINCIPAL_A },
  );
  assert.equal(claim.state, "claimed");
  assert.equal(claim.attestation.challengeId, issued.challengeId);
  assert.equal(
    (
      await coordinator.claimCaptureChallenge(issued.challenge, binding, {
        principalId: PRINCIPAL_A,
      })
    ).state,
    "in_progress",
  );
  assert.equal(await claim.release(), true);

  const retry = await coordinator.claimCaptureChallenge(
    issued.challenge,
    binding,
    { principalId: PRINCIPAL_A },
  );
  assert.equal(retry.state, "claimed");
  assert.equal(await retry.complete(), true);
  assert.equal(
    (
      await coordinator.claimCaptureChallenge(issued.challenge, binding, {
        principalId: PRINCIPAL_A,
      })
    ).state,
    "completed",
  );
  assert.equal(
    (
      await coordinator.claimCaptureChallenge(
        issued.challenge,
        { ...binding, recordSha256: "f".repeat(64) },
        { principalId: PRINCIPAL_A },
      )
    ).state,
    "rejected",
  );
  assert.equal(
    (
      await coordinator.claimCaptureChallenge(issued.challenge, binding, {
        principalId: PRINCIPAL_B,
      })
    ).state,
    "rejected",
  );
});

test("capture challenge rejects a claimed capture time outside its fresh window", async () => {
  let timestamp = Date.parse("2026-08-14T10:00:00.000Z");
  const coordinator = createMemoryCoordinator({ now: () => timestamp });
  const submissionId = "423e4567-e89b-42d3-a456-426614174000";
  const issued = await coordinator.issueCaptureChallenge(submissionId, {
    principalId: PRINCIPAL_A,
    captureWindowMs: 120_000,
    ttlMs: 900_000,
  });
  const outside = await coordinator.claimCaptureChallenge(
    issued.challenge,
    {
      submissionId,
      recordSha256: "d".repeat(64),
      manifestSha256: "e".repeat(64),
      capturedAt: "2026-08-14T10:04:00.000Z",
    },
    { principalId: PRINCIPAL_A },
  );
  assert.equal(outside.state, "outside_window");

  timestamp += 900_001;
  const expired = await coordinator.claimCaptureChallenge(
    issued.challenge,
    {
      submissionId,
      recordSha256: "d".repeat(64),
      manifestSha256: "e".repeat(64),
      capturedAt: "2026-08-14T10:01:00.000Z",
    },
    { principalId: PRINCIPAL_A },
  );
  assert.equal(expired.state, "rejected");
});

test("the authenticated user budget is enforced independently", async () => {
  const coordinator = createMemoryCoordinator();
  const binding = uploadBinding();
  const issued = await coordinator.issueUploadGrant(binding, {
    principalId: PRINCIPAL_A,
  });
  const exhausted = await coordinator.claimUploadGrant(
    issued.grant,
    binding,
    admissionOptions({
      globalBudgetLimitBytes: 1_000,
      userBudgetLimitBytes: 31,
    }),
  );
  assert.equal(exhausted.state, "user_exhausted");
  assert.equal(exhausted.usedBytes, 0);
});
