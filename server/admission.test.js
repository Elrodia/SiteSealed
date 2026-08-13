import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveUploadAdmissionConfig } from "./admission.js";

test("storage admission no longer depends on a shared upload secret", () => {
  const config = resolveUploadAdmissionConfig({ DATABASE_MODE: "required" });
  assert.equal(config.dailyLimitMiB, 2048);
  assert.equal(config.perUserDailyLimitMiB, 256);
  assert.equal(config.grantTtlMs, 900_000);
  assert.equal("secretDigest" in config, false);
  assert.equal("configured" in config, false);
});

test("global and per-user byte ceilings fail closed on invalid values", () => {
  assert.throws(
    () =>
      resolveUploadAdmissionConfig({
        STORAGE_ADMISSION_MB_PER_DAY: "24",
      }),
    /STORAGE_ADMISSION_MB_PER_DAY must be an integer/,
  );
  const config = resolveUploadAdmissionConfig({
    STORAGE_ADMISSION_MB_PER_DAY: "512",
    STORAGE_ADMISSION_MB_PER_USER_PER_DAY: "64",
  });
  assert.equal(config.dailyLimitMiB, 512);
  assert.equal(config.perUserDailyLimitMiB, 64);
  assert.throws(
    () =>
      resolveUploadAdmissionConfig({
        STORAGE_ADMISSION_MB_PER_DAY: "64",
        STORAGE_ADMISSION_MB_PER_USER_PER_DAY: "128",
      }),
    /cannot exceed/,
  );
});
