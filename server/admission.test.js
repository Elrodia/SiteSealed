import assert from "node:assert/strict";
import { test } from "node:test";
import {
  requireUploadAdmission,
  resolveUploadAdmissionConfig,
} from "./admission.js";

const ACCESS_SECRET = "alpha8-test-access-secret-32-bytes-minimum";

test("production refuses anonymous storage-grant issuance", () => {
  assert.throws(
    () => resolveUploadAdmissionConfig({ DATABASE_MODE: "required" }),
    /UPLOAD_ADMISSION_SECRET is required/,
  );
  assert.throws(
    () =>
      resolveUploadAdmissionConfig({
        DATABASE_MODE: "required",
        UPLOAD_ADMISSION_SECRET: "too-short",
      }),
    /between 32 and 256/,
  );
});

test("the controlled-alpha access secret is compared by digest", () => {
  const config = resolveUploadAdmissionConfig({
    DATABASE_MODE: "required",
    UPLOAD_ADMISSION_SECRET: ACCESS_SECRET,
    STORAGE_ADMISSION_MB_PER_DAY: "512",
  });
  assert.equal(config.configured, true);
  assert.equal(config.dailyLimitMiB, 512);
  assert.doesNotThrow(() => requireUploadAdmission(config, ACCESS_SECRET));
  assert.throws(
    () => requireUploadAdmission(config, `${ACCESS_SECRET}-wrong`),
    (error) => error.status === 403 && error.code === "UPLOAD_ADMISSION_REJECTED",
  );
});

