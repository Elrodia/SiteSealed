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

test("the shared storage budget is global, byte-based and window-scoped", async () => {
  let timestamp = 30_000;
  const coordinator = createMemoryCoordinator({ now: () => timestamp });
  const input = { bytes: 400, limitBytes: 1_000, windowMs: 1_000 };

  const first = await coordinator.consumeStorageAdmission(input);
  assert.equal(first.allowed, true);
  assert.equal(first.remainingBytes, 600);
  assert.equal((await coordinator.consumeStorageAdmission(input)).allowed, true);

  const peeked = await coordinator.readStorageAdmission({
    limitBytes: input.limitBytes,
    windowMs: input.windowMs,
  });
  assert.equal(peeked.admittedBytes, 800);
  assert.equal(peeked.remainingBytes, 200);

  const refused = await coordinator.consumeStorageAdmission(input);
  assert.equal(refused.allowed, false);
  assert.equal(refused.admittedBytes, 800);
  assert.equal(refused.remainingBytes, 200);
  assert.equal(
    (await coordinator.consumeStorageAdmission({ ...input, bytes: 200 }))
      .allowed,
    true,
  );

  timestamp = 31_001;
  assert.equal(
    (
      await coordinator.readStorageAdmission({
        limitBytes: input.limitBytes,
        windowMs: input.windowMs,
      })
    ).remainingBytes,
    1_000,
  );
  assert.equal((await coordinator.consumeStorageAdmission(input)).allowed, true);
  await assert.rejects(
    coordinator.consumeStorageAdmission({ ...input, bytes: 0 }),
    /positive size and budget/,
  );
  await assert.rejects(
    coordinator.readStorageAdmission({ limitBytes: 0, windowMs: 1_000 }),
    /positive budget/,
  );
});
