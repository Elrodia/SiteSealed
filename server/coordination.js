import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { createClient } from "redis";

const KEY_PREFIX = "sitesealed:v1.4";
const DEFAULT_RAIL_STATUS_TTL_MS = 25 * 60 * 60 * 1000;
export const UPLOAD_GRANT_TTL_MS = 15 * 60 * 1000;
export const UPLOAD_CHALLENGE_TTL_MS = 10 * 60 * 1000;
const SINGLE_USE_TOKEN_PATTERN =
  /^([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$/;
const RATE_LIMIT_SCRIPT = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {current, ttl}
`;
const STORAGE_ADMISSION_SCRIPT = `
local requested = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local existed = redis.call('EXISTS', KEYS[1])
local current = redis.call('INCRBY', KEYS[1], requested)
if existed == 0 then
  redis.call('PEXPIRE', KEYS[1], window)
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], window)
  ttl = window
end
local allowed = 1
if current > limit then
  current = redis.call('DECRBY', KEYS[1], requested)
  allowed = 0
end
return {allowed, current, ttl}
`;
const RELEASE_LOCK_SCRIPT = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`;

function dependencyMode(environment) {
  const mode = String(environment.DATABASE_MODE ?? "optional")
    .trim()
    .toLowerCase();
  if (mode !== "optional" && mode !== "required") {
    throw new Error('DATABASE_MODE must be either "optional" or "required".');
  }
  return mode;
}

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function identityDigest(identity) {
  return createHash("sha256")
    .update(`${KEY_PREFIX}:identity:${String(identity)}`)
    .digest("hex");
}

function rateKey(scope, identity) {
  const safeScope = String(scope ?? "seal").replace(/[^a-z0-9:_-]/gi, "_");
  return `${KEY_PREFIX}:rate:${safeScope}:${identityDigest(identity)}`;
}

function cacheKey(recordId) {
  return `${KEY_PREFIX}:verify:${recordId}`;
}

function lockKey(submissionId) {
  return `${KEY_PREFIX}:submission-lock:${submissionId}`;
}

function jobLockKey(name) {
  const safeName = String(name ?? "job").replace(/[^a-z0-9:_-]/gi, "_");
  return `${KEY_PREFIX}:job-lock:${safeName}`;
}

function railStatusKey(name) {
  const safeName = String(name ?? "rail").replace(/[^a-z0-9:_-]/gi, "_");
  return `${KEY_PREFIX}:runtime-rail:${safeName}`;
}

function uploadGrantKey(reference) {
  return `${KEY_PREFIX}:upload-grant:${reference}`;
}

function uploadGrantConsumedKey(reference) {
  return `${KEY_PREFIX}:upload-grant-consumed:${reference}`;
}

function uploadChallengeKey(reference) {
  return `${KEY_PREFIX}:upload-challenge:${reference}`;
}

function uploadChallengeConsumedKey(reference) {
  return `${KEY_PREFIX}:upload-challenge-consumed:${reference}`;
}

function storageAdmissionKey(scope) {
  const safeScope = String(scope ?? "global").replace(/[^a-z0-9:_-]/gi, "_");
  return `${KEY_PREFIX}:storage-admission:${safeScope}`;
}

function createSingleUseToken() {
  return `${randomUUID()}.${randomBytes(32).toString("base64url")}`;
}

function parseSingleUseToken(token) {
  const match = SINGLE_USE_TOKEN_PATTERN.exec(String(token ?? "").trim());
  return match ? { reference: match[1], secret: match[2] } : null;
}

function uploadGrantSecretDigest(secret) {
  return createHash("sha256")
    .update(`${KEY_PREFIX}:upload-grant-secret:${secret}`)
    .digest("hex");
}

function uploadChallengeSecretDigest(secret) {
  return createHash("sha256")
    .update(`${KEY_PREFIX}:upload-challenge-secret:${secret}`)
    .digest("hex");
}

function challengeDifficultyBits(value) {
  const bits = Number(value);
  if (!Number.isInteger(bits) || bits < 1 || bits > 32) {
    return null;
  }
  return bits;
}

function sameSecretDigest(left, right) {
  const leftBytes = Buffer.from(String(left), "hex");
  const rightBytes = Buffer.from(String(right), "hex");
  return (
    leftBytes.length === 32 &&
    rightBytes.length === 32 &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

function uploadGrantBinding(binding) {
  const submissionId = String(binding?.submissionId ?? "");
  const ciphertextSha256 = String(binding?.ciphertextSha256 ?? "");
  const byteLength = Number(binding?.byteLength);
  if (
    !submissionId ||
    !ciphertextSha256 ||
    !Number.isSafeInteger(byteLength) ||
    byteLength <= 0
  ) {
    return null;
  }
  return { submissionId, ciphertextSha256, byteLength };
}

function matchesUploadGrant(record, binding) {
  return (
    record.submissionId === binding.submissionId &&
    record.ciphertextSha256 === binding.ciphertextSha256 &&
    record.byteLength === binding.byteLength
  );
}

function serializeRailStatus(status) {
  if (!status || typeof status !== "object" || Array.isArray(status)) {
    throw new Error("Runtime rail status must be an object.");
  }
  const serialized = JSON.stringify(status);
  if (Buffer.byteLength(serialized, "utf8") > 8 * 1024) {
    throw new Error("Runtime rail status is unexpectedly large.");
  }
  return serialized;
}

export function resolveRedisConfig(environment = process.env) {
  const rawUrl = String(environment.REDIS_URL ?? "").trim();
  if (!rawUrl) {
    if (dependencyMode(environment) === "required") {
      throw new Error(
        "Redis is required but REDIS_URL is not configured for this service.",
      );
    }
    return null;
  }

  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("REDIS_URL must be a valid Redis connection URL.");
  }
  if (url.protocol !== "redis:" && url.protocol !== "rediss:") {
    throw new Error("REDIS_URL must use the redis:// or rediss:// protocol.");
  }
  if (!url.hostname) {
    throw new Error("REDIS_URL must include a host.");
  }

  return {
    url: rawUrl,
    verificationCacheTtlMs: positiveInteger(
      environment.VERIFICATION_CACHE_TTL_SECONDS,
      60,
    ) * 1000,
  };
}

export function createRedisCoordinator(client, options = {}) {
  const verificationCacheTtlMs = positiveInteger(
    options.verificationCacheTtlMs,
    60_000,
  );

  return {
    mode: "redis",
    persistent: false,
    authoritative: false,
    distributed: true,

    async consumeRateLimit({ scope, identity, limit, windowMs }) {
      const result = await client.eval(RATE_LIMIT_SCRIPT, {
        keys: [rateKey(scope, identity)],
        arguments: [String(windowMs)],
      });
      const count = Number(result?.[0] ?? 0);
      const ttlMs = Math.max(1, Number(result?.[1] ?? windowMs));
      return {
        allowed: count <= limit,
        count,
        limit,
        remaining: Math.max(0, limit - count),
        resetInMs: ttlMs,
      };
    },

    async consumeStorageAdmission({
      scope = "global",
      bytes,
      limitBytes,
      windowMs,
    }) {
      const requested = positiveInteger(bytes, 0);
      const limit = positiveInteger(limitBytes, 0);
      if (requested <= 0 || limit <= 0) {
        throw new Error("A storage admission needs a positive size and budget.");
      }
      const result = await client.eval(STORAGE_ADMISSION_SCRIPT, {
        keys: [storageAdmissionKey(scope)],
        arguments: [String(requested), String(limit), String(windowMs)],
      });
      const admittedBytes = Math.max(0, Number(result?.[1] ?? 0));
      const ttlMs = Math.max(1, Number(result?.[2] ?? windowMs));
      return {
        allowed: Number(result?.[0] ?? 0) === 1,
        admittedBytes,
        limitBytes: limit,
        remainingBytes: Math.max(0, limit - admittedBytes),
        resetInMs: ttlMs,
      };
    },

    async readStorageAdmission({ scope = "global", limitBytes, windowMs }) {
      const limit = positiveInteger(limitBytes, 0);
      if (limit <= 0) {
        throw new Error("A storage admission needs a positive budget.");
      }
      const key = storageAdmissionKey(scope);
      const stored = await client.get(key);
      const admittedBytes = Math.max(0, positiveInteger(stored, 0));
      const ttlMs = await client.pTTL(key);
      return {
        admittedBytes,
        limitBytes: limit,
        remainingBytes: Math.max(0, limit - admittedBytes),
        resetInMs: Number(ttlMs) > 0 ? Number(ttlMs) : windowMs,
      };
    },

    async getCachedRecord(recordId) {
      const serialized = await client.get(cacheKey(recordId));
      if (!serialized) return null;
      try {
        return JSON.parse(serialized);
      } catch {
        await client.del(cacheKey(recordId));
        return null;
      }
    },

    async setCachedRecord(recordId, record) {
      await client.set(cacheKey(recordId), JSON.stringify(record), {
        PX: verificationCacheTtlMs,
      });
    },

    async deleteCachedRecord(recordId) {
      await client.del(cacheKey(recordId));
    },

    async getRailRuntimeStatus(name) {
      const key = railStatusKey(name);
      const serialized = await client.get(key);
      if (!serialized) return null;
      try {
        return JSON.parse(serialized);
      } catch {
        await client.del(key);
        return null;
      }
    },

    async setRailRuntimeStatus(
      name,
      status,
      { ttlMs = DEFAULT_RAIL_STATUS_TTL_MS } = {},
    ) {
      const serialized = serializeRailStatus(status);
      await client.set(railStatusKey(name), serialized, {
        PX: positiveInteger(ttlMs, DEFAULT_RAIL_STATUS_TTL_MS),
      });
      return JSON.parse(serialized);
    },

    async acquireSubmissionLock(submissionId, { ttlMs = 30_000 } = {}) {
      const token = randomUUID();
      const key = lockKey(submissionId);
      const acquired = await client.set(key, token, { NX: true, PX: ttlMs });
      if (acquired !== "OK") return null;
      let released = false;
      return async () => {
        if (released) return;
        released = true;
        await client.eval(RELEASE_LOCK_SCRIPT, {
          keys: [key],
          arguments: [token],
        });
      };
    },

    async issueUploadChallenge(
      binding,
      { difficultyBits, ttlMs = UPLOAD_CHALLENGE_TTL_MS } = {},
    ) {
      const bound = uploadGrantBinding(binding);
      const bits = challengeDifficultyBits(difficultyBits);
      if (!bound || !bits) {
        throw new Error(
          "An upload challenge requires a validated binding and difficulty.",
        );
      }
      const challengeId = createSingleUseToken();
      const { reference, secret } = parseSingleUseToken(challengeId);
      const lifetimeMs = positiveInteger(ttlMs, UPLOAD_CHALLENGE_TTL_MS);
      const expiresAt = Date.now() + lifetimeMs;
      const stored = await client.set(
        uploadChallengeKey(reference),
        JSON.stringify({
          ...bound,
          difficultyBits: bits,
          secretSha256: uploadChallengeSecretDigest(secret),
          expiresAt,
        }),
        { NX: true, PX: lifetimeMs },
      );
      if (stored !== "OK") {
        throw new Error(
          "The upload challenge could not be stored for single use.",
        );
      }
      return {
        challengeId,
        difficultyBits: bits,
        expiresAt: new Date(expiresAt).toISOString(),
      };
    },

    async openUploadChallenge(challengeId, binding) {
      const parsed = parseSingleUseToken(challengeId);
      const bound = uploadGrantBinding(binding);
      if (!parsed || !bound) return null;
      const serialized = await client.get(uploadChallengeKey(parsed.reference));
      if (!serialized) return null;
      let record;
      try {
        record = JSON.parse(serialized);
      } catch {
        return null;
      }
      const bits = challengeDifficultyBits(record.difficultyBits);
      if (
        !bits ||
        !sameSecretDigest(
          uploadChallengeSecretDigest(parsed.secret),
          record.secretSha256,
        ) ||
        !matchesUploadGrant(record, bound)
      ) {
        return null;
      }
      const expiresAt = Number(record.expiresAt);
      if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return null;
      const consumedKey = uploadChallengeConsumedKey(parsed.reference);
      const consumed = Boolean(await client.get(consumedKey));
      return {
        consumed,
        difficultyBits: bits,
        expiresAt: new Date(expiresAt).toISOString(),
        async consume() {
          const claimed = await client.set(consumedKey, "1", {
            NX: true,
            PX: Math.max(1, expiresAt - Date.now()),
          });
          return claimed === "OK";
        },
      };
    },

    async issueUploadGrant(binding, { ttlMs = UPLOAD_GRANT_TTL_MS } = {}) {
      const bound = uploadGrantBinding(binding);
      if (!bound) throw new Error("An upload grant requires a validated binding.");
      const grantId = createSingleUseToken();
      const { reference, secret } = parseSingleUseToken(grantId);
      const lifetimeMs = positiveInteger(ttlMs, UPLOAD_GRANT_TTL_MS);
      const expiresAt = Date.now() + lifetimeMs;
      const stored = await client.set(
        uploadGrantKey(reference),
        JSON.stringify({
          ...bound,
          secretSha256: uploadGrantSecretDigest(secret),
          expiresAt,
        }),
        { NX: true, PX: lifetimeMs },
      );
      if (stored !== "OK") {
        throw new Error("The upload grant could not be stored for single use.");
      }
      return { grantId, expiresAt: new Date(expiresAt).toISOString() };
    },

    async openUploadGrant(grantId, binding) {
      const parsed = parseSingleUseToken(grantId);
      const bound = uploadGrantBinding(binding);
      if (!parsed || !bound) return null;
      const serialized = await client.get(uploadGrantKey(parsed.reference));
      if (!serialized) return null;
      let record;
      try {
        record = JSON.parse(serialized);
      } catch {
        return null;
      }
      if (
        !sameSecretDigest(
          uploadGrantSecretDigest(parsed.secret),
          record.secretSha256,
        ) ||
        !matchesUploadGrant(record, bound)
      ) {
        return null;
      }
      const expiresAt = Number(record.expiresAt);
      if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return null;
      const consumedKey = uploadGrantConsumedKey(parsed.reference);
      const consumed = Boolean(await client.get(consumedKey));
      return {
        consumed,
        expiresAt: new Date(expiresAt).toISOString(),
        async consume() {
          const claimed = await client.set(consumedKey, "1", {
            NX: true,
            PX: Math.max(1, expiresAt - Date.now()),
          });
          return claimed === "OK";
        },
      };
    },

    async acquireJobLock(name, { ttlMs = 10 * 60 * 1000 } = {}) {
      const token = randomUUID();
      const key = jobLockKey(name);
      const acquired = await client.set(key, token, { NX: true, PX: ttlMs });
      if (acquired !== "OK") return null;
      let released = false;
      return async () => {
        if (released) return;
        released = true;
        await client.eval(RELEASE_LOCK_SCRIPT, {
          keys: [key],
          arguments: [token],
        });
      };
    },

    async healthCheck() {
      const probeKey = `${KEY_PREFIX}:health:${randomUUID()}`;
      await client.set(probeKey, "ok", { PX: 5_000 });
      const value = await client.get(probeKey);
      await client.del(probeKey);
      if (value !== "ok") {
        throw new Error("Redis health probe could not read its transient value.");
      }
      return {
        mode: "redis",
        status: "connected",
        persistent: false,
        writable: true,
        authoritative: false,
        distributed: true,
        rateLimiting: true,
        storageAdmission: true,
        verificationCache: true,
        runtimeRailStatus: true,
      };
    },

    async close() {
      if (!client.isOpen) return;
      await client.quit();
    },
  };
}

export function createMemoryCoordinator({ now = () => Date.now() } = {}) {
  const rateLimits = new Map();
  const cachedRecords = new Map();
  const locks = new Map();
  const railStatuses = new Map();
  const uploadGrants = new Map();
  const uploadChallenges = new Map();
  const storageAdmissions = new Map();

  function removeExpired(timestamp) {
    for (const [key, entry] of rateLimits) {
      if (entry.resetAt <= timestamp) rateLimits.delete(key);
    }
    for (const [key, entry] of cachedRecords) {
      if (entry.expiresAt <= timestamp) cachedRecords.delete(key);
    }
    for (const [key, entry] of locks) {
      if (entry.expiresAt <= timestamp) locks.delete(key);
    }
    for (const [key, entry] of railStatuses) {
      if (entry.expiresAt <= timestamp) railStatuses.delete(key);
    }
    for (const [key, entry] of uploadGrants) {
      if (entry.expiresAt <= timestamp) uploadGrants.delete(key);
    }
    for (const [key, entry] of uploadChallenges) {
      if (entry.expiresAt <= timestamp) uploadChallenges.delete(key);
    }
    for (const [key, entry] of storageAdmissions) {
      if (entry.resetAt <= timestamp) storageAdmissions.delete(key);
    }
  }

  return {
    mode: "memory",
    persistent: false,
    authoritative: false,
    distributed: false,

    async consumeRateLimit({ scope, identity, limit, windowMs }) {
      const timestamp = now();
      removeExpired(timestamp);
      const key = rateKey(scope, identity);
      const entry = rateLimits.get(key) ?? {
        count: 0,
        resetAt: timestamp + windowMs,
      };
      entry.count += 1;
      rateLimits.set(key, entry);
      return {
        allowed: entry.count <= limit,
        count: entry.count,
        limit,
        remaining: Math.max(0, limit - entry.count),
        resetInMs: Math.max(1, entry.resetAt - timestamp),
      };
    },

    async consumeStorageAdmission({
      scope = "global",
      bytes,
      limitBytes,
      windowMs,
    }) {
      const requested = positiveInteger(bytes, 0);
      const limit = positiveInteger(limitBytes, 0);
      if (requested <= 0 || limit <= 0) {
        throw new Error("A storage admission needs a positive size and budget.");
      }
      const timestamp = now();
      removeExpired(timestamp);
      const key = storageAdmissionKey(scope);
      const entry = storageAdmissions.get(key) ?? {
        bytes: 0,
        resetAt: timestamp + windowMs,
      };
      const allowed = entry.bytes + requested <= limit;
      if (allowed) entry.bytes += requested;
      storageAdmissions.set(key, entry);
      return {
        allowed,
        admittedBytes: entry.bytes,
        limitBytes: limit,
        remainingBytes: Math.max(0, limit - entry.bytes),
        resetInMs: Math.max(1, entry.resetAt - timestamp),
      };
    },

    async readStorageAdmission({ scope = "global", limitBytes, windowMs }) {
      const limit = positiveInteger(limitBytes, 0);
      if (limit <= 0) {
        throw new Error("A storage admission needs a positive budget.");
      }
      const timestamp = now();
      removeExpired(timestamp);
      const entry = storageAdmissions.get(storageAdmissionKey(scope));
      const admittedBytes = entry?.bytes ?? 0;
      return {
        admittedBytes,
        limitBytes: limit,
        remainingBytes: Math.max(0, limit - admittedBytes),
        resetInMs: entry
          ? Math.max(1, entry.resetAt - timestamp)
          : Number(windowMs),
      };
    },

    async getCachedRecord(recordId) {
      const timestamp = now();
      removeExpired(timestamp);
      return cachedRecords.get(cacheKey(recordId))?.record ?? null;
    },

    async setCachedRecord(recordId, record, { ttlMs = 60_000 } = {}) {
      cachedRecords.set(cacheKey(recordId), {
        record: structuredClone(record),
        expiresAt: now() + ttlMs,
      });
    },

    async deleteCachedRecord(recordId) {
      cachedRecords.delete(cacheKey(recordId));
    },

    async getRailRuntimeStatus(name) {
      const timestamp = now();
      removeExpired(timestamp);
      const entry = railStatuses.get(railStatusKey(name));
      return entry ? JSON.parse(entry.serialized) : null;
    },

    async setRailRuntimeStatus(
      name,
      status,
      { ttlMs = DEFAULT_RAIL_STATUS_TTL_MS } = {},
    ) {
      const serialized = serializeRailStatus(status);
      railStatuses.set(railStatusKey(name), {
        serialized,
        expiresAt:
          now() + positiveInteger(ttlMs, DEFAULT_RAIL_STATUS_TTL_MS),
      });
      return JSON.parse(serialized);
    },

    async acquireSubmissionLock(submissionId, { ttlMs = 30_000 } = {}) {
      const timestamp = now();
      removeExpired(timestamp);
      const key = lockKey(submissionId);
      if (locks.has(key)) return null;
      const token = randomUUID();
      locks.set(key, { token, expiresAt: timestamp + ttlMs });
      let released = false;
      return async () => {
        if (released) return;
        released = true;
        if (locks.get(key)?.token === token) locks.delete(key);
      };
    },

    async issueUploadChallenge(
      binding,
      { difficultyBits, ttlMs = UPLOAD_CHALLENGE_TTL_MS } = {},
    ) {
      const timestamp = now();
      removeExpired(timestamp);
      const bound = uploadGrantBinding(binding);
      const bits = challengeDifficultyBits(difficultyBits);
      if (!bound || !bits) {
        throw new Error(
          "An upload challenge requires a validated binding and difficulty.",
        );
      }
      const challengeId = createSingleUseToken();
      const { reference, secret } = parseSingleUseToken(challengeId);
      const expiresAt =
        timestamp + positiveInteger(ttlMs, UPLOAD_CHALLENGE_TTL_MS);
      uploadChallenges.set(uploadChallengeKey(reference), {
        ...bound,
        difficultyBits: bits,
        secretSha256: uploadChallengeSecretDigest(secret),
        expiresAt,
        consumed: false,
      });
      return {
        challengeId,
        difficultyBits: bits,
        expiresAt: new Date(expiresAt).toISOString(),
      };
    },

    async openUploadChallenge(challengeId, binding) {
      const timestamp = now();
      removeExpired(timestamp);
      const parsed = parseSingleUseToken(challengeId);
      const bound = uploadGrantBinding(binding);
      if (!parsed || !bound) return null;
      const record = uploadChallenges.get(uploadChallengeKey(parsed.reference));
      if (!record) return null;
      const bits = challengeDifficultyBits(record.difficultyBits);
      if (
        !bits ||
        !sameSecretDigest(
          uploadChallengeSecretDigest(parsed.secret),
          record.secretSha256,
        ) ||
        !matchesUploadGrant(record, bound) ||
        record.expiresAt <= timestamp
      ) {
        return null;
      }
      return {
        consumed: record.consumed,
        difficultyBits: bits,
        expiresAt: new Date(record.expiresAt).toISOString(),
        async consume() {
          if (record.consumed) return false;
          record.consumed = true;
          return true;
        },
      };
    },

    async issueUploadGrant(binding, { ttlMs = UPLOAD_GRANT_TTL_MS } = {}) {
      const timestamp = now();
      removeExpired(timestamp);
      const bound = uploadGrantBinding(binding);
      if (!bound) throw new Error("An upload grant requires a validated binding.");
      const grantId = createSingleUseToken();
      const { reference, secret } = parseSingleUseToken(grantId);
      const expiresAt =
        timestamp + positiveInteger(ttlMs, UPLOAD_GRANT_TTL_MS);
      uploadGrants.set(uploadGrantKey(reference), {
        ...bound,
        secretSha256: uploadGrantSecretDigest(secret),
        expiresAt,
        consumed: false,
      });
      return { grantId, expiresAt: new Date(expiresAt).toISOString() };
    },

    async openUploadGrant(grantId, binding) {
      const timestamp = now();
      removeExpired(timestamp);
      const parsed = parseSingleUseToken(grantId);
      const bound = uploadGrantBinding(binding);
      if (!parsed || !bound) return null;
      const record = uploadGrants.get(uploadGrantKey(parsed.reference));
      if (!record) return null;
      if (
        !sameSecretDigest(
          uploadGrantSecretDigest(parsed.secret),
          record.secretSha256,
        ) ||
        !matchesUploadGrant(record, bound) ||
        record.expiresAt <= timestamp
      ) {
        return null;
      }
      return {
        consumed: record.consumed,
        expiresAt: new Date(record.expiresAt).toISOString(),
        async consume() {
          if (record.consumed) return false;
          record.consumed = true;
          return true;
        },
      };
    },

    async acquireJobLock(name, { ttlMs = 10 * 60 * 1000 } = {}) {
      const timestamp = now();
      removeExpired(timestamp);
      const key = jobLockKey(name);
      if (locks.has(key)) return null;
      const token = randomUUID();
      locks.set(key, { token, expiresAt: timestamp + ttlMs });
      let released = false;
      return async () => {
        if (released) return;
        released = true;
        if (locks.get(key)?.token === token) locks.delete(key);
      };
    },

    async healthCheck() {
      return {
        mode: "memory",
        status: "not_configured",
        persistent: false,
        writable: true,
        authoritative: false,
        distributed: false,
        rateLimiting: true,
        storageAdmission: true,
        verificationCache: true,
        runtimeRailStatus: true,
      };
    },

    async close() {},
  };
}

export async function createRedisCoordinatorFromEnv(
  environment = process.env,
) {
  const config = resolveRedisConfig(environment);
  if (!config) return null;
  const client = createClient({
    url: config.url,
    socket: { connectTimeout: 8_000 },
  });
  client.on("error", (error) => {
    console.error(`Redis client error: ${error.message}`);
  });
  try {
    await client.connect();
    const coordinator = createRedisCoordinator(client, config);
    await coordinator.healthCheck();
    return coordinator;
  } catch (error) {
    if (client.isOpen) await client.quit().catch(() => {});
    throw error;
  }
}
