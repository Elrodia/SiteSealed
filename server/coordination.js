import { createHash, randomUUID } from "node:crypto";
import { createClient } from "redis";

const KEY_PREFIX = "sitesealed:v1.3";
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
        verificationCache: true,
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

    async healthCheck() {
      return {
        mode: "memory",
        status: "not_configured",
        persistent: false,
        writable: true,
        authoritative: false,
        distributed: false,
        rateLimiting: true,
        verificationCache: true,
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
