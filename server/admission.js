const MIB = 1024 * 1024;

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

export function resolveUploadAdmissionConfig(environment = process.env) {
  const dailyLimitMiB = boundedInteger(
    environment.STORAGE_ADMISSION_MB_PER_DAY,
    2048,
    25,
    102400,
    "STORAGE_ADMISSION_MB_PER_DAY",
  );
  const perUserDailyLimitMiB = boundedInteger(
    environment.STORAGE_ADMISSION_MB_PER_USER_PER_DAY,
    256,
    25,
    10240,
    "STORAGE_ADMISSION_MB_PER_USER_PER_DAY",
  );
  const grantTtlSeconds = boundedInteger(
    environment.UPLOAD_GRANT_TTL_SECONDS,
    900,
    60,
    3600,
    "UPLOAD_GRANT_TTL_SECONDS",
  );
  if (perUserDailyLimitMiB > dailyLimitMiB) {
    throw new Error(
      "STORAGE_ADMISSION_MB_PER_USER_PER_DAY cannot exceed STORAGE_ADMISSION_MB_PER_DAY.",
    );
  }
  return {
    dailyLimitBytes: dailyLimitMiB * MIB,
    dailyLimitMiB,
    perUserDailyLimitBytes: perUserDailyLimitMiB * MIB,
    perUserDailyLimitMiB,
    budgetWindowMs: 24 * 60 * 60 * 1000,
    grantTtlMs: grantTtlSeconds * 1000,
  };
}
