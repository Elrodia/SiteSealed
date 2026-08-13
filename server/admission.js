import { createHash, timingSafeEqual } from "node:crypto";
import { ApiError } from "./records.js";

const MIB = 1024 * 1024;
const MINIMUM_SECRET_BYTES = 32;
const MAXIMUM_SECRET_BYTES = 256;

function dependencyMode(environment) {
  const mode = String(environment.DATABASE_MODE ?? "optional")
    .trim()
    .toLowerCase();
  if (mode !== "optional" && mode !== "required") {
    throw new Error('DATABASE_MODE must be either "optional" or "required".');
  }
  return mode;
}

function boundedInteger(value, fallback, minimum, maximum, variableName) {
  const raw = String(value ?? "").trim();
  const parsed = raw ? Number.parseInt(raw, 10) : fallback;
  if (
    !Number.isSafeInteger(parsed) ||
    parsed < minimum ||
    parsed > maximum
  ) {
    throw new Error(
      `${variableName} must be an integer between ${minimum} and ${maximum}.`,
    );
  }
  return parsed;
}

function secretDigest(secret) {
  return createHash("sha256")
    .update("sitesealed:v1.4:upload-admission\0", "utf8")
    .update(secret, "utf8")
    .digest();
}

export function resolveUploadAdmissionConfig(environment = process.env) {
  const secret = String(environment.UPLOAD_ADMISSION_SECRET ?? "").trim();
  if (!secret && dependencyMode(environment) === "required") {
    throw new Error(
      "UPLOAD_ADMISSION_SECRET is required in DATABASE_MODE=required so anonymous callers cannot mint storage grants.",
    );
  }
  const secretBytes = Buffer.byteLength(secret, "utf8");
  if (
    secret &&
    (secretBytes < MINIMUM_SECRET_BYTES || secretBytes > MAXIMUM_SECRET_BYTES)
  ) {
    throw new Error(
      `UPLOAD_ADMISSION_SECRET must contain between ${MINIMUM_SECRET_BYTES} and ${MAXIMUM_SECRET_BYTES} UTF-8 bytes.`,
    );
  }

  const dailyLimitMiB = boundedInteger(
    environment.STORAGE_ADMISSION_MB_PER_DAY,
    2048,
    25,
    102400,
    "STORAGE_ADMISSION_MB_PER_DAY",
  );
  const grantTtlSeconds = boundedInteger(
    environment.UPLOAD_GRANT_TTL_SECONDS,
    900,
    60,
    3600,
    "UPLOAD_GRANT_TTL_SECONDS",
  );
  return {
    configured: Boolean(secret),
    secretDigest: secret ? secretDigest(secret) : null,
    dailyLimitBytes: dailyLimitMiB * MIB,
    dailyLimitMiB,
    budgetWindowMs: 24 * 60 * 60 * 1000,
    grantTtlMs: grantTtlSeconds * 1000,
  };
}

export function requireUploadAdmission(config, suppliedSecret) {
  if (!config?.configured || !Buffer.isBuffer(config.secretDigest)) {
    throw new ApiError(
      503,
      "UPLOAD_ADMISSION_NOT_CONFIGURED",
      "Encrypted-original deposits are unavailable until the operator configures the controlled-alpha access secret.",
    );
  }

  const candidate = String(suppliedSecret ?? "").trim();
  const candidateBytes = Buffer.byteLength(candidate, "utf8");
  const candidateDigest =
    candidateBytes >= MINIMUM_SECRET_BYTES &&
    candidateBytes <= MAXIMUM_SECRET_BYTES
      ? secretDigest(candidate)
      : Buffer.alloc(config.secretDigest.length);

  if (!timingSafeEqual(candidateDigest, config.secretDigest)) {
    throw new ApiError(
      403,
      "UPLOAD_ADMISSION_REJECTED",
      "The controlled-alpha deposit access code is not valid.",
    );
  }
}
