import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { createClient } from "redis";

const KEY_PREFIX = "sitesealed:v1.4";
const DEFAULT_RAIL_STATUS_TTL_MS = 25 * 60 * 60 * 1000;
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
const RELEASE_LOCK_SCRIPT = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`;
const CLAIM_UPLOAD_GRANT_SCRIPT = `
local raw = redis.call('GET', KEYS[1])
if not raw then
  return {'REJECTED'}
end
local entry = cjson.decode(raw)
if entry.secretDigest ~= ARGV[1] or entry.bindingDigest ~= ARGV[2] then
  return {'REJECTED'}
end
if entry.state == 'completed' then
  return {'COMPLETED', cjson.encode(entry.descriptor)}
end
if entry.state == 'claimed' then
  return {'IN_PROGRESS'}
end
local bytes = tonumber(ARGV[4])
local limit = tonumber(ARGV[5])
local total = tonumber(redis.call('GET', KEYS[2]) or '0')
if not entry.budgetDebited then
  if total + bytes > limit then
    local budgetTtl = redis.call('PTTL', KEYS[2])
    if budgetTtl < 1 then budgetTtl = tonumber(ARGV[6]) end
    return {'EXHAUSTED', tostring(budgetTtl), tostring(total)}
  end
  total = redis.call('INCRBY', KEYS[2], bytes)
  local budgetTtl = redis.call('PTTL', KEYS[2])
  if budgetTtl < 0 then
    redis.call('PEXPIRE', KEYS[2], ARGV[6])
  end
  entry.budgetDebited = true
end
entry.state = 'claimed'
entry.claimToken = ARGV[3]
local grantTtl = redis.call('PTTL', KEYS[1])
if grantTtl < 1 then
  return {'REJECTED'}
end
redis.call('SET', KEYS[1], cjson.encode(entry), 'PX', grantTtl)
return {'CLAIMED', tostring(math.max(0, limit - total))}
`;
const COMPLETE_UPLOAD_GRANT_SCRIPT = `
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local entry = cjson.decode(raw)
if entry.state ~= 'claimed' or entry.claimToken ~= ARGV[1] then return 0 end
entry.state = 'completed'
entry.descriptor = cjson.decode(ARGV[2])
entry.claimToken = nil
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1 then return 0 end
redis.call('SET', KEYS[1], cjson.encode(entry), 'PX', ttl)
return 1
`;
const RELEASE_UPLOAD_GRANT_SCRIPT = `
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local entry = cjson.decode(raw)
if entry.state ~= 'claimed' or entry.claimToken ~= ARGV[1] then return 0 end
entry.state = 'ready'
entry.claimToken = nil
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1 then return 0 end
redis.call('SET', KEYS[1], cjson.encode(entry), 'PX', ttl)
return 1
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

function uploadGrantKey(grantId) {
  return `${KEY_PREFIX}:upload-grant:${grantId}`;
}

function storageAdmissionKey() {
  return `${KEY_PREFIX}:storage-admission:global`;
}

function uploadBindingDigest(binding) {
  return createHash("sha256")
    .update(`${KEY_PREFIX}:upload-binding\0`)
    .update(JSON.stringify(binding))
    .digest("hex");
}

function uploadGrantSecretDigest(grantId, secret) {
  return createHash("sha256")
    .update(`${KEY_PREFIX}:upload-grant-secret:${grantId}\0`)
    .update(secret)
    .digest("hex");
}

function parseUploadGrant(value) {
  const token = String(value ?? "").trim();
  const match = token.match(
    /^([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$/,
  );
  return match ? { grantId: match[1], secret: match[2] } : null;
}

function safeHexEqual(left, right) {
  const leftBytes = Buffer.from(String(left ?? ""), "hex");
  const rightBytes = Buffer.from(String(right ?? ""), "hex");
  return (
    leftBytes.length === 32 &&
    rightBytes.length === 32 &&
    timingSafeEqual(leftBytes, rightBytes)
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
  const now = typeof options.now === "function" ? options.now : Date.now;

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

    async issueUploadGrant(binding, { ttlMs = 15 * 60 * 1000 } = {}) {
      const normalizedTtlMs = positiveInteger(ttlMs, 15 * 60 * 1000);
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const grantId = randomUUID();
        const secret = randomBytes(32).toString("base64url");
        const entry = {
          state: "ready",
          secretDigest: uploadGrantSecretDigest(grantId, secret),
          bindingDigest: uploadBindingDigest(binding),
          binding: structuredClone(binding),
          budgetDebited: false,
        };
        const stored = await client.set(
          uploadGrantKey(grantId),
          JSON.stringify(entry),
          { NX: true, PX: normalizedTtlMs },
        );
        if (stored === "OK") {
          return {
            grant: `${grantId}.${secret}`,
            expiresAt: new Date(now() + normalizedTtlMs).toISOString(),
          };
        }
      }
      throw new Error("Could not allocate a unique upload grant identifier.");
    },

    async claimUploadGrant(
      grant,
      binding,
      {
        budgetLimitBytes,
        budgetWindowMs = 24 * 60 * 60 * 1000,
      } = {},
    ) {
      const parsed = parseUploadGrant(grant);
      if (!parsed) return { state: "rejected" };
      const claimToken = randomUUID();
      const normalizedBudgetLimitBytes = positiveInteger(
        budgetLimitBytes,
        2 * 1024 * 1024 * 1024,
      );
      const result = await client.eval(CLAIM_UPLOAD_GRANT_SCRIPT, {
        keys: [uploadGrantKey(parsed.grantId), storageAdmissionKey()],
        arguments: [
          uploadGrantSecretDigest(parsed.grantId, parsed.secret),
          uploadBindingDigest(binding),
          claimToken,
          String(binding.ciphertextBytes),
          String(normalizedBudgetLimitBytes),
          String(positiveInteger(budgetWindowMs, 24 * 60 * 60 * 1000)),
        ],
      });
      const state = String(result?.[0] ?? "REJECTED");
      if (state === "REJECTED") return { state: "rejected" };
      if (state === "IN_PROGRESS") return { state: "in_progress" };
      if (state === "EXHAUSTED") {
        return {
          state: "exhausted",
          resetInMs: Math.max(1, Number(result?.[1] ?? budgetWindowMs)),
          usedBytes: Math.max(0, Number(result?.[2] ?? 0)),
        };
      }
      if (state === "COMPLETED") {
        return {
          state: "completed",
          descriptor: JSON.parse(String(result?.[1] ?? "null")),
        };
      }
      if (state !== "CLAIMED") {
        throw new Error(`Unexpected Redis upload grant state: ${state}.`);
      }

      let settled = false;
      return {
        state: "claimed",
        binding: structuredClone(binding),
        admissionRemainingBytes: Math.max(0, Number(result?.[1] ?? 0)),
        async complete(descriptor) {
          if (settled) return false;
          const completed = await client.eval(COMPLETE_UPLOAD_GRANT_SCRIPT, {
            keys: [uploadGrantKey(parsed.grantId)],
            arguments: [claimToken, JSON.stringify(descriptor)],
          });
          if (Number(completed) === 1) settled = true;
          return Number(completed) === 1;
        },
        async release() {
          if (settled) return false;
          const released = await client.eval(RELEASE_UPLOAD_GRANT_SCRIPT, {
            keys: [uploadGrantKey(parsed.grantId)],
            arguments: [claimToken],
          });
          if (Number(released) === 1) settled = true;
          return Number(released) === 1;
        },
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
        uploadGrants: true,
        boundedStorageAdmission: true,
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
  let storageAdmission = null;

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
    if (storageAdmission?.resetAt <= timestamp) storageAdmission = null;
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

    async issueUploadGrant(binding, { ttlMs = 15 * 60 * 1000 } = {}) {
      const timestamp = now();
      removeExpired(timestamp);
      const normalizedTtlMs = positiveInteger(ttlMs, 15 * 60 * 1000);
      const grantId = randomUUID();
      const secret = randomBytes(32).toString("base64url");
      uploadGrants.set(uploadGrantKey(grantId), {
        state: "ready",
        secretDigest: uploadGrantSecretDigest(grantId, secret),
        bindingDigest: uploadBindingDigest(binding),
        binding: structuredClone(binding),
        budgetDebited: false,
        expiresAt: timestamp + normalizedTtlMs,
      });
      return {
        grant: `${grantId}.${secret}`,
        expiresAt: new Date(timestamp + normalizedTtlMs).toISOString(),
      };
    },

    async claimUploadGrant(
      grant,
      binding,
      {
        budgetLimitBytes = 2 * 1024 * 1024 * 1024,
        budgetWindowMs = 24 * 60 * 60 * 1000,
      } = {},
    ) {
      const timestamp = now();
      removeExpired(timestamp);
      const parsed = parseUploadGrant(grant);
      if (!parsed) return { state: "rejected" };
      const key = uploadGrantKey(parsed.grantId);
      const entry = uploadGrants.get(key);
      const suppliedSecretDigest = uploadGrantSecretDigest(
        parsed.grantId,
        parsed.secret,
      );
      if (
        !entry ||
        !safeHexEqual(entry.secretDigest, suppliedSecretDigest) ||
        !safeHexEqual(entry.bindingDigest, uploadBindingDigest(binding))
      ) {
        return { state: "rejected" };
      }
      if (entry.state === "completed") {
        return {
          state: "completed",
          descriptor: structuredClone(entry.descriptor),
        };
      }
      if (entry.state === "claimed") {
        return { state: "in_progress" };
      }

      const normalizedBudgetLimitBytes = positiveInteger(
        budgetLimitBytes,
        2 * 1024 * 1024 * 1024,
      );
      const normalizedBudgetWindowMs = positiveInteger(
        budgetWindowMs,
        24 * 60 * 60 * 1000,
      );
      storageAdmission ??= {
        usedBytes: 0,
        resetAt: timestamp + normalizedBudgetWindowMs,
      };
      if (
        !entry.budgetDebited &&
        storageAdmission.usedBytes + binding.ciphertextBytes >
          normalizedBudgetLimitBytes
      ) {
        return {
          state: "exhausted",
          resetInMs: Math.max(1, storageAdmission.resetAt - timestamp),
          usedBytes: storageAdmission.usedBytes,
        };
      }
      if (!entry.budgetDebited) {
        storageAdmission.usedBytes += binding.ciphertextBytes;
        entry.budgetDebited = true;
      }

      const claimToken = randomUUID();
      entry.state = "claimed";
      entry.claimToken = claimToken;
      let settled = false;
      return {
        state: "claimed",
        binding: structuredClone(entry.binding),
        admissionRemainingBytes: Math.max(
          0,
          normalizedBudgetLimitBytes - storageAdmission.usedBytes,
        ),
        async complete(descriptor) {
          if (settled) return false;
          const current = uploadGrants.get(key);
          if (
            current?.state !== "claimed" ||
            current.claimToken !== claimToken
          ) {
            return false;
          }
          current.state = "completed";
          current.descriptor = structuredClone(descriptor);
          delete current.claimToken;
          settled = true;
          return true;
        },
        async release() {
          if (settled) return false;
          const current = uploadGrants.get(key);
          if (
            current?.state !== "claimed" ||
            current.claimToken !== claimToken
          ) {
            return false;
          }
          current.state = "ready";
          delete current.claimToken;
          settled = true;
          return true;
        },
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
        uploadGrants: true,
        boundedStorageAdmission: true,
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
