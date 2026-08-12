import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { Certificate } from "pkijs";
import {
  EVIDENCY_SANDBOX_ROOT_SHA256,
  Rfc3161VerificationError,
  assertTimestampSignerProfile,
  createEvidencySandboxTrustStore,
  verifyRfc3161Token,
} from "./rfc3161.js";

const fixture = JSON.parse(
  readFileSync(
    new URL("./fixtures/evidency-sandbox-token-20260812.json", import.meta.url),
    "utf8",
  ),
);
const token = Buffer.from(fixture.tokenBase64, "base64");

function verify(overrides = {}) {
  return verifyRfc3161Token({
    token,
    expectedDigest: fixture.evidenceDigest,
    expectedSerialNumber: fixture.serialNumber,
    expectedCertifiedAt: fixture.certifiedAt,
    expectedPolicyId: fixture.tsaPolicyId,
    ...overrides,
  });
}

function rejectsWithCode(code) {
  return (error) => {
    assert.ok(error instanceof Rfc3161VerificationError);
    assert.equal(error.code, code);
    return true;
  };
}

test("independently verifies the real Evidency sandbox RFC 3161 token", async () => {
  const result = await verify();
  assert.equal(result.signatureVerification, "VALID");
  assert.equal(
    result.certificateChainVerification,
    "VALID_TO_PINNED_SANDBOX_ROOT",
  );
  assert.equal(result.signingCertificateVerification, "ESSCERTIDV2_MATCH");
  assert.equal(result.signingCertificateHashAlgorithm, "SHA384");
  assert.equal(result.cmsAlgorithmProtection, "VALID");
  assert.equal(result.cmsDigestAlgorithm, "SHA512");
  assert.equal(result.cmsSignatureAlgorithm, "RSA_PKCS1_SHA512");
  assert.equal(result.hashedMessage, fixture.evidenceDigest);
  assert.equal(result.serialNumber, fixture.serialNumber);
  assert.equal(result.certifiedAt, fixture.certifiedAt);
  assert.equal(result.tsaPolicyId, fixture.tsaPolicyId);
  assert.equal(result.tokenSha256, fixture.tokenSha256);
  assert.equal(result.trustAnchorSha256, EVIDENCY_SANDBOX_ROOT_SHA256);
  assert.equal(result.certificatePathLength, 3);
  assert.equal(result.revocationVerification, "NOT_CHECKED");
});

test("rejects a token when the SiteSealed evidence digest differs", async () => {
  await assert.rejects(
    verify({ expectedDigest: "0".repeat(64) }),
    rejectsWithCode("MESSAGE_IMPRINT_MISMATCH"),
  );
});

test("rejects a cryptographically modified CMS signature", async () => {
  const tampered = Buffer.from(token);
  tampered[tampered.length - 1] ^= 0x01;
  await assert.rejects(
    verify({ token: tampered }),
    rejectsWithCode("CMS_SIGNATURE_INVALID"),
  );
});

test("rejects provider metadata that contradicts the signed TSTInfo", async () => {
  await assert.rejects(
    verify({ expectedSerialNumber: "01" }),
    rejectsWithCode("PROVIDER_SERIAL_MISMATCH"),
  );
  await assert.rejects(
    verify({ expectedCertifiedAt: "2026-08-12T19:31:55.000Z" }),
    rejectsWithCode("PROVIDER_TIME_MISMATCH"),
  );
  await assert.rejects(
    verify({ expectedPolicyId: "1.2.3" }),
    rejectsWithCode("PROVIDER_POLICY_MISMATCH"),
  );
});

test("fails closed if a release-pinned trust certificate changes", () => {
  assert.throws(
    () =>
      createEvidencySandboxTrustStore({
        rootSha256: "0".repeat(64),
      }),
    rejectsWithCode("TRUST_BUNDLE_INTEGRITY_FAILED"),
  );
});

test("rejects a CA certificate as an RFC 3161 timestamp signer", () => {
  const timestampCaPem = readFileSync(
    new URL("./trust/evidency-sandbox-timestamp-ca.pem", import.meta.url),
  );
  const x509 = new X509Certificate(timestampCaPem);
  const certificate = Certificate.fromBER(x509.raw);
  assert.throws(
    () => assertTimestampSignerProfile(certificate, x509),
    rejectsWithCode("SIGNER_CERTIFICATE_PROFILE_INVALID"),
  );
});
