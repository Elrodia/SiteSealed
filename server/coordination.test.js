import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createMemoryCoordinator,
  createRedisCoordinator,
  resolveRedisConfig,
} from "./coordination.js";

class FakeQuotaRedisClient {
  constructor(now) {
    this.now = now;
    this.grants = new Map();
    this.values = new Map();
    this.sets = new Map();
    this.reservationBytes = new Map();
    this.reservationExpiries = new Map();
    this.isOpen = false;
  }

  cleanupReservations(reservedKey, expiriesKey, bytesKey, timestamp) {
    const expiries = this.reservationExpiries.get(expiriesKey) ?? new Map();
    const bytes = this.reservationBytes.get(bytesKey) ?? new Map();
    let reserved = Number(this.values.get(reservedKey) ?? 0);
    for (const [grantId, expiresAt] of expiries) {
      if (expiresAt > timestamp) continue;
      reserved = Math.max(0, reserved - Number(bytes.get(grantId) ?? 0));
      expiries.delete(grantId);
      bytes.delete(grantId);
    }
    this.reservationExpiries.set(expiriesKey, expiries);
    this.reservationBytes.set(bytesKey, bytes);
    this.values.set(reservedKey, reserved);
    return reserved;
  }

  grant(key) {
    const stored = this.grants.get(key);
    if (!stored || stored.expiresAt <= this.now()) {
      this.grants.delete(key);
      return null;
    }
    return stored;
  }

  async eval(script, { keys, arguments: args }) {
    if (script.includes("SITESEALED_ACCOUNT_QUOTA_ISSUE")) {
      const [
        grantKey,
        usedKey,
        objectsKey,
        reservedKey,
        expiriesKey,
        bytesKey,
      ] = keys;
      const timestamp = Number(args[2]);
      let reserved = this.cleanupReservations(
        reservedKey,
        expiriesKey,
        bytesKey,
        timestamp,
      );
      const used = Number(this.values.get(usedKey) ?? 0);
      const objects = this.sets.get(objectsKey) ?? new Set();
      let requestedBytes = Number(args[4]);
      if (objects.has(args[7])) requestedBytes = 0;
      if (used + reserved + requestedBytes > Number(args[5])) {
        return ["QUOTA_EXCEEDED", String(used), String(reserved)];
      }
      if (this.grants.has(grantKey)) {
        return ["COLLISION", String(used), String(reserved)];
      }
      const entry = JSON.parse(args[0]);
      entry.reservationBytes = requestedBytes;
      entry.storageObjectDigest = args[7];
      entry.expiresAtMs = Number(args[3]);
      this.grants.set(grantKey, {
        entry,
        expiresAt: Number(args[3]),
      });
      if (requestedBytes > 0) {
        reserved += requestedBytes;
        this.values.set(reservedKey, reserved);
        const bytes = this.reservationBytes.get(bytesKey) ?? new Map();
        const expiries = this.reservationExpiries.get(expiriesKey) ?? new Map();
        bytes.set(args[6], requestedBytes);
        expiries.set(args[6], Number(args[3]));
        this.reservationBytes.set(bytesKey, bytes);
        this.reservationExpiries.set(expiriesKey, expiries);
      }
      return ["ISSUED", String(used), String(reserved)];
    }

    if (script.includes("SITESEALED_ACCOUNT_QUOTA_USAGE")) {
      const [usedKey, reservedKey, expiriesKey, bytesKey] = keys;
      const reserved = this.cleanupReservations(
        reservedKey,
        expiriesKey,
        bytesKey,
        Number(args[0]),
      );
      return [String(this.values.get(usedKey) ?? 0), String(reserved)];
    }

    if (script.includes("SITESEALED_ACCOUNT_QUOTA_COMPLETE")) {
      const [
        grantKey,
        usedKey,
        objectsKey,
        reservedKey,
        expiriesKey,
        bytesKey,
      ] = keys;
      const stored = this.grant(grantKey);
      if (
        !stored ||
        stored.entry.state !== "claimed" ||
        stored.entry.claimToken !== args[0]
      ) {
        return [0];
      }
      const bytes = this.reservationBytes.get(bytesKey) ?? new Map();
      const expiries = this.reservationExpiries.get(expiriesKey) ?? new Map();
      const reservation = Number(bytes.get(args[2]) ?? 0);
      if (reservation > 0) {
        this.values.set(
          reservedKey,
          Math.max(
            0,
            Number(this.values.get(reservedKey) ?? 0) - reservation,
          ),
        );
      }
      bytes.delete(args[2]);
      expiries.delete(args[2]);
      const objects = this.sets.get(objectsKey) ?? new Set();
      const storageObjectDigest = stored.entry.storageObjectDigest ?? args[3];
      const added = objects.has(storageObjectDigest) ? 0 : 1;
      objects.add(storageObjectDigest);
      this.sets.set(objectsKey, objects);
      let used = Number(this.values.get(usedKey) ?? 0);
      if (added === 1) {
        used += Number(stored.entry.binding.ciphertextBytes);
        this.values.set(usedKey, used);
      }
      stored.entry.state = "completed";
      stored.entry.descriptor = JSON.parse(args[1]);
      delete stored.entry.claimToken;
      return [1, String(used), String(added)];
    }

    if (script.includes("GLOBAL_EXHAUSTED")) {
      const [grantKey, globalKey, userKey] = keys;
      const stored = this.grant(grantKey);
      if (!stored) return ["REJECTED"];
      const entry = stored.entry;
      if (
        entry.secretDigest !== args[0] ||
        entry.bindingDigest !== args[1] ||
        entry.principalDigest !== args[2]
      ) {
        return ["REJECTED"];
      }
      if (entry.state === "completed") {
        return ["COMPLETED", JSON.stringify(entry.descriptor)];
      }
      if (entry.state === "claimed") return ["IN_PROGRESS"];
      const requested = Number(args[4]);
      const globalLimit = Number(args[5]);
      const userLimit = Number(args[6]);
      let globalUsed = Number(this.values.get(globalKey) ?? 0);
      let userUsed = Number(this.values.get(userKey) ?? 0);
      if (!entry.budgetDebited) {
        if (globalUsed + requested > globalLimit) {
          return ["GLOBAL_EXHAUSTED", args[7], String(globalUsed)];
        }
        if (userUsed + requested > userLimit) {
          return ["USER_EXHAUSTED", args[7], String(userUsed)];
        }
        globalUsed += requested;
        userUsed += requested;
        this.values.set(globalKey, globalUsed);
        this.values.set(userKey, userUsed);
        entry.budgetDebited = true;
      }
      entry.state = "claimed";
      entry.claimToken = args[3];
      return [
        "CLAIMED",
        String(globalLimit - globalUsed),
        String(userLimit - userUsed),
      ];
    }

    throw new Error("Unexpected Redis script in quota test double.");
  }
}

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

async function exerciseAccountQuota(createCoordinator) {
  let timestamp = 1_000;
  const coordinator = createCoordinator(() => timestamp);
  const quotaBytes = 48;
  const firstBinding = uploadBinding({
    ciphertextBytes: 32,
    ciphertextSha256: "1".repeat(64),
  });
  const secondBinding = uploadBinding({
    submissionId: "223e4567-e89b-42d3-a456-426614174000",
    ciphertextBytes: 32,
    ciphertextSha256: "2".repeat(64),
  });
  const concurrent = await Promise.all([
    coordinator.issueUploadGrant(firstBinding, {
      ttlMs: 500,
      principalId: PRINCIPAL_A,
      quotaBytes,
    }),
    coordinator.issueUploadGrant(secondBinding, {
      ttlMs: 500,
      principalId: PRINCIPAL_A,
      quotaBytes,
    }),
  ]);
  const concurrentStates = concurrent
    .map(({ state }) => state ?? "issued")
    .sort();

  timestamp = 1_501;
  const afterExpiry = await coordinator.issueUploadGrant(secondBinding, {
    ttlMs: 5_000,
    principalId: PRINCIPAL_A,
    quotaBytes,
  });
  const claim = await coordinator.claimUploadGrant(
    afterExpiry.grant,
    secondBinding,
    admissionOptions({
      globalBudgetLimitBytes: 1_000,
      userBudgetLimitBytes: 1_000,
    }),
  );
  assert.equal(claim.state, "claimed");
  assert.equal(
    await claim.complete({
      objectKey: "sealed/v1.2/idempotent.ssenc",
      ciphertextBytes: 32,
    }),
    true,
  );

  const identical = await coordinator.issueUploadGrant(secondBinding, {
    ttlMs: 5_000,
    principalId: PRINCIPAL_A,
    quotaBytes,
  });
  const replayClaim = await coordinator.claimUploadGrant(
    identical.grant,
    secondBinding,
    admissionOptions({
      globalBudgetLimitBytes: 1_000,
      userBudgetLimitBytes: 1_000,
    }),
  );
  assert.equal(replayClaim.state, "claimed");
  assert.equal(
    await replayClaim.complete({
      objectKey: "sealed/v1.2/idempotent.ssenc",
      ciphertextBytes: 32,
    }),
    true,
  );

  const usage = await coordinator.getAccountStorageUsage(PRINCIPAL_A, {
    quotaBytes,
  });
  const overQuota = await coordinator.issueUploadGrant(
    uploadBinding({
      submissionId: "323e4567-e89b-42d3-a456-426614174000",
      ciphertextBytes: 17,
      ciphertextSha256: "3".repeat(64),
    }),
    { principalId: PRINCIPAL_A, quotaBytes },
  );
  return {
    concurrentStates,
    afterExpiry: afterExpiry.state ?? "issued",
    identical: identical.state ?? "issued",
    usage,
    overQuota: {
      state: overQuota.state,
      usedBytes: overQuota.usedBytes,
      quotaBytes: overQuota.quotaBytes,
    },
  };
}

test("memory and Redis account quotas reserve concurrently, expire and deduplicate identically", async () => {
  const memory = await exerciseAccountQuota((now) =>
    createMemoryCoordinator({ now }),
  );
  const redis = await exerciseAccountQuota((now) =>
    createRedisCoordinator(new FakeQuotaRedisClient(now), { now }),
  );
  const expected = {
    concurrentStates: ["issued", "quota_exceeded"],
    afterExpiry: "issued",
    identical: "issued",
    usage: { usedBytes: 32, quotaBytes: 48 },
    overQuota: {
      state: "quota_exceeded",
      usedBytes: 32,
      quotaBytes: 48,
    },
  };
  assert.deepEqual(memory, expected);
  assert.deepEqual(redis, expected);
});
