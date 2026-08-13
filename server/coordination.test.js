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

test("upload grants are exact-bound, single-claim and replay-safe", async () => {
  const coordinator = createMemoryCoordinator();
  const binding = uploadBinding();
  const issued = await coordinator.issueUploadGrant(binding, { ttlMs: 60_000 });
  assert.match(issued.grant, /^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/);

  const claim = await coordinator.claimUploadGrant(issued.grant, binding, {
    budgetLimitBytes: 64,
  });
  assert.equal(claim.state, "claimed");
  assert.equal(
    (await coordinator.claimUploadGrant(issued.grant, binding, {
      budgetLimitBytes: 64,
    })).state,
    "in_progress",
  );
  assert.equal(await claim.release(), true);

  const retry = await coordinator.claimUploadGrant(issued.grant, binding, {
    budgetLimitBytes: 64,
  });
  assert.equal(retry.state, "claimed");
  const descriptor = { objectKey: "sealed/v1.2/object.ssenc" };
  assert.equal(await retry.complete(descriptor), true);
  const replay = await coordinator.claimUploadGrant(issued.grant, binding, {
    budgetLimitBytes: 64,
  });
  assert.equal(replay.state, "completed");
  assert.deepEqual(replay.descriptor, descriptor);

  const mismatch = await coordinator.claimUploadGrant(
    issued.grant,
    uploadBinding({ ciphertextSha256: "d".repeat(64) }),
    { budgetLimitBytes: 64 },
  );
  assert.equal(mismatch.state, "rejected");
});

test("the global storage budget is charged once per claimed grant", async () => {
  const coordinator = createMemoryCoordinator();
  const firstBinding = uploadBinding();
  const secondBinding = uploadBinding({
    submissionId: "223e4567-e89b-42d3-a456-426614174000",
    ciphertextSha256: "d".repeat(64),
  });
  const first = await coordinator.issueUploadGrant(firstBinding);
  const second = await coordinator.issueUploadGrant(secondBinding);
  const firstClaim = await coordinator.claimUploadGrant(
    first.grant,
    firstBinding,
    { budgetLimitBytes: 32 },
  );
  assert.equal(firstClaim.state, "claimed");
  await firstClaim.release();
  const retry = await coordinator.claimUploadGrant(first.grant, firstBinding, {
    budgetLimitBytes: 32,
  });
  assert.equal(retry.state, "claimed");
  const exhausted = await coordinator.claimUploadGrant(
    second.grant,
    secondBinding,
    { budgetLimitBytes: 32 },
  );
  assert.equal(exhausted.state, "exhausted");
  assert.equal(exhausted.usedBytes, 32);
});

test("expired upload grants fail closed", async () => {
  let timestamp = 1_000;
  const coordinator = createMemoryCoordinator({ now: () => timestamp });
  const binding = uploadBinding();
  const issued = await coordinator.issueUploadGrant(binding, { ttlMs: 500 });
  timestamp = 1_501;
  assert.equal(
    (await coordinator.claimUploadGrant(issued.grant, binding)).state,
    "rejected",
  );
});

test("an active upload claim cannot be stolen before the grant expires", async () => {
  let timestamp = 1_000;
  const coordinator = createMemoryCoordinator({ now: () => timestamp });
  const binding = uploadBinding();
  const issued = await coordinator.issueUploadGrant(binding, { ttlMs: 60_000 });
  const claim = await coordinator.claimUploadGrant(issued.grant, binding);
  assert.equal(claim.state, "claimed");

  timestamp = 31_000;
  assert.equal(
    (await coordinator.claimUploadGrant(issued.grant, binding)).state,
    "in_progress",
  );
  assert.equal(await claim.release(), true);
});
