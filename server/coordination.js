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
if entry.secretDigest ~= ARGV[1] or entry.bindingDigest ~= ARGV[2] or entry.principalDigest ~= ARGV[3] then
  return {'REJECTED'}
end
if entry.state == 'completed' then
  return {'COMPLETED', cjson.encode(entry.descriptor)}
end
if entry.state == 'claimed' then
  return {'IN_PROGRESS'}
end
local bytes = tonumber(ARGV[5])
local globalLimit = tonumber(ARGV[6])
local userLimit = tonumber(ARGV[7])
local globalTotal = tonumber(redis.call('GET', KEYS[2]) or '0')
local userTotal = tonumber(redis.call('GET', KEYS[3]) or '0')
if not entry.budgetDebited then
  if globalTotal + bytes > globalLimit then
    local budgetTtl = redis.call('PTTL', KEYS[2])
    if budgetTtl < 1 then budgetTtl = tonumber(ARGV[8]) end
    return {'GLOBAL_EXHAUSTED', tostring(budgetTtl), tostring(globalTotal)}
  end
  if userTotal + bytes > userLimit then
    local budgetTtl = redis.call('PTTL', KEYS[3])
    if budgetTtl < 1 then budgetTtl = tonumber(ARGV[8]) end
    return {'USER_EXHAUSTED', tostring(budgetTtl), tostring(userTotal)}
  end
  globalTotal = redis.call('INCRBY', KEYS[2], bytes)
  userTotal = redis.call('INCRBY', KEYS[3], bytes)
  if redis.call('PTTL', KEYS[2]) < 0 then
    redis.call('PEXPIRE', KEYS[2], ARGV[8])
  end
  if redis.call('PTTL', KEYS[3]) < 0 then
    redis.call('PEXPIRE', KEYS[3], ARGV[8])
  end
  entry.budgetDebited = true
end
entry.state = 'claimed'
entry.claimToken = ARGV[4]
local grantTtl = redis.call('PTTL', KEYS[1])
if grantTtl < 1 then
  return {'REJECTED'}
end
redis.call('SET', KEYS[1], cjson.encode(entry), 'PX', grantTtl)
return {'CLAIMED', tostring(math.max(0, globalLimit - globalTotal)), tostring(math.max(0, userLimit - userTotal))}
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
const CLAIM_CAPTURE_CHALLENGE_SCRIPT = `
local raw = redis.call('GET', KEYS[1])
if not raw then return {'REJECTED'} end
local entry = cjson.decode(raw)
if entry.secretDigest ~= ARGV[1] or entry.principalDigest ~= ARGV[2] or entry.submissionId ~= ARGV[3] then
  return {'REJECTED'}
end
if entry.state == 'completed' then
  if entry.bindingDigest ~= ARGV[4] then return {'REJECTED'} end
  return {'COMPLETED', cjson.encode(entry.attestation)}
end
if entry.state == 'claimed' then return {'IN_PROGRESS'} end
local capturedAtMs = tonumber(ARGV[6])
if capturedAtMs < (tonumber(entry.issuedAtMs) - 60000) or capturedAtMs > (tonumber(entry.captureExpiresAtMs) + 60000) then
  return {'OUTSIDE_WINDOW'}
end
entry.state = 'claimed'
entry.bindingDigest = ARGV[4]
entry.claimToken = ARGV[5]
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1 then return {'REJECTED'} end
redis.call('SET', KEYS[1], cjson.encode(entry), 'PX', ttl)
return {'CLAIMED', cjson.encode(entry.attestation)}
`;
const COMPLETE_CAPTURE_CHALLENGE_SCRIPT = `
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local entry = cjson.decode(raw)
if entry.state ~= 'claimed' or entry.claimToken ~= ARGV[1] then return 0 end
entry.state = 'completed'
entry.claimToken = nil
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1 then return 0 end
redis.call('SET', KEYS[1], cjson.encode(entry), 'PX', ttl)
return 1
`;
const RELEASE_CAPTURE_CHALLENGE_SCRIPT = `
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local entry = cjson.decode(raw)
if entry.state ~= 'claimed' or entry.claimToken ~= ARGV[1] then return 0 end
entry.state = 'ready'
entry.bindingDigest = nil
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

function captureChallengeKey(challengeId) {
  return `${KEY_PREFIX}:capture-challenge:${challengeId}`;
}

function storageAdmissionKey() {
  return `${KEY_PREFIX}:storage-admission:global`;
}

function userStorageAdmissionKey(principalDigest) {
  return `${KEY_PREFIX}:storage-admission:user:${principalDigest}`;
}

function authSessionKey(token) {
  const digest = createHash("sha256")
    .update(`${KEY_PREFIX}:auth-session\0`)
    .update(token)
    .digest("hex");
  return `${KEY_PREFIX}:auth-session:${digest}`;
}

function principalDigest(principalId) {
  return createHash("sha256")
    .update(`${KEY_PREFIX}:principal\0`)
    .update(String(principalId ?? ""))
    .digest("hex");
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

function captureChallengeSecretDigest(challengeId, secret) {
  return createHash("sha256")
    .update(`${KEY_PREFIX}:capture-challenge-secret:${challengeId}\0`)
    .update(secret)
    .digest("hex");
}

function captureBindingDigest(binding) {
  return createHash("sha256")
    .update(`${KEY_PREFIX}:capture-binding\0`)
    .update(JSON.stringify(binding))
    .digest("hex");
}

function parseUploadGrant(value) {
  const token = String(value ?? "").trim();
  const match = token.match(
    /^([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$/,
  );
  return match ? { grantId: match[1], secret: match[2] } : null;
}

function parseCaptureChallenge(value) {
  const token = String(value ?? "").trim();
  const match = token.match(
    /^([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$/,
  );
  return match ? { challengeId: match[1], secret: match[2] } : null;
}

function parseSessionToken(value) {
  const token = String(value ?? "").trim();
  return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}

function normalizedPrincipalId(value) {
  const id = String(value ?? "").trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(id) ? id : null;
}

function normalizedSessionUser(user) {
  const id = normalizedPrincipalId(user?.id);
  const email = String(user?.email ?? "").trim().toLowerCase();
  const name = String(user?.name ?? "").trim().slice(0, 160);
  if (
    !id ||
    user?.provider !== "GOOGLE" ||
    !email ||
    email.length > 320 ||
    !email.includes("@")
  ) {
    throw new Error("A valid Google account identity is required.");
  }
  return { id, provider: "GOOGLE", email, name: name || email };
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

    async issueUploadGrant(
      binding,
      { ttlMs = 15 * 60 * 1000, principalId: ownerId } = {},
    ) {
      const normalizedTtlMs = positiveInteger(ttlMs, 15 * 60 * 1000);
      const ownerPrincipalId = normalizedPrincipalId(ownerId);
      if (!ownerPrincipalId) {
        throw new Error("Upload grants require an authenticated principal.");
      }
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const grantId = randomUUID();
        const secret = randomBytes(32).toString("base64url");
        const entry = {
          state: "ready",
          secretDigest: uploadGrantSecretDigest(grantId, secret),
          bindingDigest: uploadBindingDigest(binding),
          principalDigest: principalDigest(ownerPrincipalId),
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

    async issueCaptureChallenge(
      submissionId,
      {
        principalId: ownerId,
        captureWindowMs = 2 * 60 * 1000,
        ttlMs = 15 * 60 * 1000,
      } = {},
    ) {
      const ownerPrincipalId = normalizedPrincipalId(ownerId);
      if (!ownerPrincipalId) {
        throw new Error("Capture challenges require an authenticated principal.");
      }
      const normalizedCaptureWindowMs = positiveInteger(
        captureWindowMs,
        2 * 60 * 1000,
      );
      const normalizedTtlMs = Math.max(
        normalizedCaptureWindowMs + 60_000,
        positiveInteger(ttlMs, 15 * 60 * 1000),
      );
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const challengeId = randomUUID();
        const secret = randomBytes(32).toString("base64url");
        const issuedAtMs = now();
        const captureExpiresAtMs = issuedAtMs + normalizedCaptureWindowMs;
        const attestation = {
          challengeId,
          submissionId,
          issuedAt: new Date(issuedAtMs).toISOString(),
          captureExpiresAt: new Date(captureExpiresAtMs).toISOString(),
          timeAuthority: "SITESEALED_SERVER_CHALLENGE",
        };
        const entry = {
          state: "ready",
          secretDigest: captureChallengeSecretDigest(challengeId, secret),
          principalDigest: principalDigest(ownerPrincipalId),
          submissionId,
          issuedAtMs,
          captureExpiresAtMs,
          attestation,
        };
        const stored = await client.set(
          captureChallengeKey(challengeId),
          JSON.stringify(entry),
          { NX: true, PX: normalizedTtlMs },
        );
        if (stored === "OK") {
          return {
            challenge: `${challengeId}.${secret}`,
            ...attestation,
            claimExpiresAt: new Date(issuedAtMs + normalizedTtlMs).toISOString(),
          };
        }
      }
      throw new Error("Could not allocate a unique capture challenge identifier.");
    },

    async claimCaptureChallenge(
      challenge,
      binding,
      { principalId: ownerId } = {},
    ) {
      const parsed = parseCaptureChallenge(challenge);
      const ownerPrincipalId = normalizedPrincipalId(ownerId);
      if (!parsed || !ownerPrincipalId) return { state: "rejected" };
      const capturedAtMs = Date.parse(binding?.capturedAt);
      if (!Number.isFinite(capturedAtMs)) return { state: "rejected" };
      const claimToken = randomUUID();
      const result = await client.eval(CLAIM_CAPTURE_CHALLENGE_SCRIPT, {
        keys: [captureChallengeKey(parsed.challengeId)],
        arguments: [
          captureChallengeSecretDigest(parsed.challengeId, parsed.secret),
          principalDigest(ownerPrincipalId),
          String(binding.submissionId),
          captureBindingDigest(binding),
          claimToken,
          String(capturedAtMs),
        ],
      });
      const state = String(result?.[0] ?? "REJECTED");
      if (state === "REJECTED") return { state: "rejected" };
      if (state === "IN_PROGRESS") return { state: "in_progress" };
      if (state === "OUTSIDE_WINDOW") return { state: "outside_window" };
      const attestation = JSON.parse(String(result?.[1] ?? "null"));
      if (state === "COMPLETED") {
        return { state: "completed", attestation };
      }
      if (state !== "CLAIMED") {
        throw new Error(`Unexpected Redis capture challenge state: ${state}.`);
      }
      let settled = false;
      return {
        state: "claimed",
        attestation,
        async complete() {
          if (settled) return false;
          const completed = await client.eval(
            COMPLETE_CAPTURE_CHALLENGE_SCRIPT,
            {
              keys: [captureChallengeKey(parsed.challengeId)],
              arguments: [claimToken],
            },
          );
          if (Number(completed) === 1) settled = true;
          return Number(completed) === 1;
        },
        async release() {
          if (settled) return false;
          const released = await client.eval(
            RELEASE_CAPTURE_CHALLENGE_SCRIPT,
            {
              keys: [captureChallengeKey(parsed.challengeId)],
              arguments: [claimToken],
            },
          );
          if (Number(released) === 1) settled = true;
          return Number(released) === 1;
        },
      };
    },

    async claimUploadGrant(
      grant,
      binding,
      {
        principalId: ownerId,
        globalBudgetLimitBytes,
        userBudgetLimitBytes,
        budgetWindowMs = 24 * 60 * 60 * 1000,
      } = {},
    ) {
      const parsed = parseUploadGrant(grant);
      const ownerPrincipalId = normalizedPrincipalId(ownerId);
      if (!parsed || !ownerPrincipalId) return { state: "rejected" };
      const claimToken = randomUUID();
      const normalizedGlobalBudgetLimitBytes = positiveInteger(
        globalBudgetLimitBytes,
        2 * 1024 * 1024 * 1024,
      );
      const normalizedUserBudgetLimitBytes = positiveInteger(
        userBudgetLimitBytes,
        256 * 1024 * 1024,
      );
      const ownerDigest = principalDigest(ownerPrincipalId);
      const result = await client.eval(CLAIM_UPLOAD_GRANT_SCRIPT, {
        keys: [
          uploadGrantKey(parsed.grantId),
          storageAdmissionKey(),
          userStorageAdmissionKey(ownerDigest),
        ],
        arguments: [
          uploadGrantSecretDigest(parsed.grantId, parsed.secret),
          uploadBindingDigest(binding),
          ownerDigest,
          claimToken,
          String(binding.ciphertextBytes),
          String(normalizedGlobalBudgetLimitBytes),
          String(normalizedUserBudgetLimitBytes),
          String(positiveInteger(budgetWindowMs, 24 * 60 * 60 * 1000)),
        ],
      });
      const state = String(result?.[0] ?? "REJECTED");
      if (state === "REJECTED") return { state: "rejected" };
      if (state === "IN_PROGRESS") return { state: "in_progress" };
      if (state === "GLOBAL_EXHAUSTED" || state === "USER_EXHAUSTED") {
        return {
          state:
            state === "USER_EXHAUSTED"
              ? "user_exhausted"
              : "global_exhausted",
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
        globalAdmissionRemainingBytes: Math.max(
          0,
          Number(result?.[1] ?? 0),
        ),
        userAdmissionRemainingBytes: Math.max(
          0,
          Number(result?.[2] ?? 0),
        ),
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

    async createAuthSession(user, { ttlMs = 7 * 24 * 60 * 60 * 1000 } = {}) {
      const normalizedUser = normalizedSessionUser(user);
      const normalizedTtlMs = positiveInteger(
        ttlMs,
        7 * 24 * 60 * 60 * 1000,
      );
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const token = randomBytes(32).toString("base64url");
        const csrfToken = randomBytes(32).toString("base64url");
        const expiresAt = new Date(now() + normalizedTtlMs).toISOString();
        const stored = await client.set(
          authSessionKey(token),
          JSON.stringify({ user: normalizedUser, csrfToken, expiresAt }),
          { NX: true, PX: normalizedTtlMs },
        );
        if (stored === "OK") {
          return { token, csrfToken, expiresAt, user: normalizedUser };
        }
      }
      throw new Error("Could not allocate a unique authenticated session.");
    },

    async getAuthSession(value) {
      const token = parseSessionToken(value);
      if (!token) return null;
      const serialized = await client.get(authSessionKey(token));
      if (!serialized) return null;
      try {
        const session = JSON.parse(serialized);
        return {
          user: normalizedSessionUser(session.user),
          csrfToken: String(session.csrfToken ?? ""),
          expiresAt: String(session.expiresAt ?? ""),
        };
      } catch {
        await client.del(authSessionKey(token));
        return null;
      }
    },

    async deleteAuthSession(value) {
      const token = parseSessionToken(value);
      if (!token) return false;
      return (await client.del(authSessionKey(token))) === 1;
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
        accountSessions: true,
        uploadGrants: true,
        captureChallenges: true,
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
  const captureChallenges = new Map();
  const authSessions = new Map();
  const userStorageAdmissions = new Map();
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
    for (const [key, entry] of captureChallenges) {
      if (entry.expiresAt <= timestamp) captureChallenges.delete(key);
    }
    for (const [key, entry] of authSessions) {
      if (entry.expiresAtTimestamp <= timestamp) authSessions.delete(key);
    }
    for (const [key, entry] of userStorageAdmissions) {
      if (entry.resetAt <= timestamp) userStorageAdmissions.delete(key);
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

    async issueUploadGrant(
      binding,
      { ttlMs = 15 * 60 * 1000, principalId: ownerId } = {},
    ) {
      const timestamp = now();
      removeExpired(timestamp);
      const normalizedTtlMs = positiveInteger(ttlMs, 15 * 60 * 1000);
      const ownerPrincipalId = normalizedPrincipalId(ownerId);
      if (!ownerPrincipalId) {
        throw new Error("Upload grants require an authenticated principal.");
      }
      const grantId = randomUUID();
      const secret = randomBytes(32).toString("base64url");
      uploadGrants.set(uploadGrantKey(grantId), {
        state: "ready",
        secretDigest: uploadGrantSecretDigest(grantId, secret),
        bindingDigest: uploadBindingDigest(binding),
        principalDigest: principalDigest(ownerPrincipalId),
        binding: structuredClone(binding),
        budgetDebited: false,
        expiresAt: timestamp + normalizedTtlMs,
      });
      return {
        grant: `${grantId}.${secret}`,
        expiresAt: new Date(timestamp + normalizedTtlMs).toISOString(),
      };
    },

    async issueCaptureChallenge(
      submissionId,
      {
        principalId: ownerId,
        captureWindowMs = 2 * 60 * 1000,
        ttlMs = 15 * 60 * 1000,
      } = {},
    ) {
      const timestamp = now();
      removeExpired(timestamp);
      const ownerPrincipalId = normalizedPrincipalId(ownerId);
      if (!ownerPrincipalId) {
        throw new Error("Capture challenges require an authenticated principal.");
      }
      const normalizedCaptureWindowMs = positiveInteger(
        captureWindowMs,
        2 * 60 * 1000,
      );
      const normalizedTtlMs = Math.max(
        normalizedCaptureWindowMs + 60_000,
        positiveInteger(ttlMs, 15 * 60 * 1000),
      );
      const challengeId = randomUUID();
      const secret = randomBytes(32).toString("base64url");
      const captureExpiresAtMs = timestamp + normalizedCaptureWindowMs;
      const attestation = {
        challengeId,
        submissionId,
        issuedAt: new Date(timestamp).toISOString(),
        captureExpiresAt: new Date(captureExpiresAtMs).toISOString(),
        timeAuthority: "SITESEALED_SERVER_CHALLENGE",
      };
      captureChallenges.set(captureChallengeKey(challengeId), {
        state: "ready",
        secretDigest: captureChallengeSecretDigest(challengeId, secret),
        principalDigest: principalDigest(ownerPrincipalId),
        submissionId,
        issuedAtMs: timestamp,
        captureExpiresAtMs,
        attestation,
        expiresAt: timestamp + normalizedTtlMs,
      });
      return {
        challenge: `${challengeId}.${secret}`,
        ...attestation,
        claimExpiresAt: new Date(timestamp + normalizedTtlMs).toISOString(),
      };
    },

    async claimCaptureChallenge(
      challenge,
      binding,
      { principalId: ownerId } = {},
    ) {
      const timestamp = now();
      removeExpired(timestamp);
      const parsed = parseCaptureChallenge(challenge);
      const ownerPrincipalId = normalizedPrincipalId(ownerId);
      if (!parsed || !ownerPrincipalId) return { state: "rejected" };
      const key = captureChallengeKey(parsed.challengeId);
      const entry = captureChallenges.get(key);
      const suppliedSecretDigest = captureChallengeSecretDigest(
        parsed.challengeId,
        parsed.secret,
      );
      const bindingDigest = captureBindingDigest(binding);
      if (
        !entry ||
        !safeHexEqual(entry.secretDigest, suppliedSecretDigest) ||
        !safeHexEqual(entry.principalDigest, principalDigest(ownerPrincipalId)) ||
        entry.submissionId !== binding?.submissionId
      ) {
        return { state: "rejected" };
      }
      if (entry.state === "completed") {
        return safeHexEqual(entry.bindingDigest, bindingDigest)
          ? { state: "completed", attestation: structuredClone(entry.attestation) }
          : { state: "rejected" };
      }
      if (entry.state === "claimed") return { state: "in_progress" };
      const capturedAtMs = Date.parse(binding?.capturedAt);
      if (
        !Number.isFinite(capturedAtMs) ||
        capturedAtMs < entry.issuedAtMs - 60_000 ||
        capturedAtMs > entry.captureExpiresAtMs + 60_000
      ) {
        return { state: "outside_window" };
      }
      const claimToken = randomUUID();
      entry.state = "claimed";
      entry.bindingDigest = bindingDigest;
      entry.claimToken = claimToken;
      let settled = false;
      return {
        state: "claimed",
        attestation: structuredClone(entry.attestation),
        async complete() {
          if (settled) return false;
          const current = captureChallenges.get(key);
          if (current?.state !== "claimed" || current.claimToken !== claimToken) {
            return false;
          }
          current.state = "completed";
          delete current.claimToken;
          settled = true;
          return true;
        },
        async release() {
          if (settled) return false;
          const current = captureChallenges.get(key);
          if (current?.state !== "claimed" || current.claimToken !== claimToken) {
            return false;
          }
          current.state = "ready";
          delete current.bindingDigest;
          delete current.claimToken;
          settled = true;
          return true;
        },
      };
    },

    async claimUploadGrant(
      grant,
      binding,
      {
        principalId: ownerId,
        globalBudgetLimitBytes = 2 * 1024 * 1024 * 1024,
        userBudgetLimitBytes = 256 * 1024 * 1024,
        budgetWindowMs = 24 * 60 * 60 * 1000,
      } = {},
    ) {
      const timestamp = now();
      removeExpired(timestamp);
      const parsed = parseUploadGrant(grant);
      const ownerPrincipalId = normalizedPrincipalId(ownerId);
      if (!parsed || !ownerPrincipalId) return { state: "rejected" };
      const key = uploadGrantKey(parsed.grantId);
      const entry = uploadGrants.get(key);
      const ownerDigest = principalDigest(ownerPrincipalId);
      const suppliedSecretDigest = uploadGrantSecretDigest(
        parsed.grantId,
        parsed.secret,
      );
      if (
        !entry ||
        !safeHexEqual(entry.secretDigest, suppliedSecretDigest) ||
        !safeHexEqual(entry.bindingDigest, uploadBindingDigest(binding)) ||
        !safeHexEqual(entry.principalDigest, ownerDigest)
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

      const normalizedGlobalBudgetLimitBytes = positiveInteger(
        globalBudgetLimitBytes,
        2 * 1024 * 1024 * 1024,
      );
      const normalizedUserBudgetLimitBytes = positiveInteger(
        userBudgetLimitBytes,
        256 * 1024 * 1024,
      );
      const normalizedBudgetWindowMs = positiveInteger(
        budgetWindowMs,
        24 * 60 * 60 * 1000,
      );
      storageAdmission ??= {
        usedBytes: 0,
        resetAt: timestamp + normalizedBudgetWindowMs,
      };
      const userAdmission = userStorageAdmissions.get(ownerDigest) ?? {
        usedBytes: 0,
        resetAt: timestamp + normalizedBudgetWindowMs,
      };
      userStorageAdmissions.set(ownerDigest, userAdmission);
      if (
        !entry.budgetDebited &&
        storageAdmission.usedBytes + binding.ciphertextBytes >
          normalizedGlobalBudgetLimitBytes
      ) {
        return {
          state: "global_exhausted",
          resetInMs: Math.max(1, storageAdmission.resetAt - timestamp),
          usedBytes: storageAdmission.usedBytes,
        };
      }
      if (
        !entry.budgetDebited &&
        userAdmission.usedBytes + binding.ciphertextBytes >
          normalizedUserBudgetLimitBytes
      ) {
        return {
          state: "user_exhausted",
          resetInMs: Math.max(1, userAdmission.resetAt - timestamp),
          usedBytes: userAdmission.usedBytes,
        };
      }
      if (!entry.budgetDebited) {
        storageAdmission.usedBytes += binding.ciphertextBytes;
        userAdmission.usedBytes += binding.ciphertextBytes;
        entry.budgetDebited = true;
      }

      const claimToken = randomUUID();
      entry.state = "claimed";
      entry.claimToken = claimToken;
      let settled = false;
      return {
        state: "claimed",
        binding: structuredClone(entry.binding),
        globalAdmissionRemainingBytes: Math.max(
          0,
          normalizedGlobalBudgetLimitBytes - storageAdmission.usedBytes,
        ),
        userAdmissionRemainingBytes: Math.max(
          0,
          normalizedUserBudgetLimitBytes - userAdmission.usedBytes,
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

    async createAuthSession(user, { ttlMs = 7 * 24 * 60 * 60 * 1000 } = {}) {
      const timestamp = now();
      removeExpired(timestamp);
      const normalizedUser = normalizedSessionUser(user);
      const normalizedTtlMs = positiveInteger(
        ttlMs,
        7 * 24 * 60 * 60 * 1000,
      );
      const token = randomBytes(32).toString("base64url");
      const csrfToken = randomBytes(32).toString("base64url");
      const expiresAtTimestamp = timestamp + normalizedTtlMs;
      const expiresAt = new Date(expiresAtTimestamp).toISOString();
      authSessions.set(authSessionKey(token), {
        user: normalizedUser,
        csrfToken,
        expiresAt,
        expiresAtTimestamp,
      });
      return { token, csrfToken, expiresAt, user: normalizedUser };
    },

    async getAuthSession(value) {
      const timestamp = now();
      removeExpired(timestamp);
      const token = parseSessionToken(value);
      if (!token) return null;
      const session = authSessions.get(authSessionKey(token));
      if (!session) return null;
      return {
        user: structuredClone(session.user),
        csrfToken: session.csrfToken,
        expiresAt: session.expiresAt,
      };
    },

    async deleteAuthSession(value) {
      const token = parseSessionToken(value);
      if (!token) return false;
      return authSessions.delete(authSessionKey(token));
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
        accountSessions: true,
        uploadGrants: true,
        captureChallenges: true,
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
