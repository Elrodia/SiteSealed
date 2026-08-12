import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  createEvidencyTimestampService,
  normalizeEvidencyTimestamp,
  resolveEvidencyConfig,
} from "./evidency.js";

const fixture = JSON.parse(
  readFileSync(
    new URL("./fixtures/evidency-sandbox-token-20260812.json", import.meta.url),
    "utf8",
  ),
);
const digest = fixture.evidenceDigest;
const token = fixture.tokenBase64;

test("Evidency configuration is disabled by default and strict in sandbox mode", () => {
  assert.equal(resolveEvidencyConfig({}), null);
  assert.throws(
    () => resolveEvidencyConfig({ EVIDENCY_MODE: "sandbox" }),
    /EVIDENCY_API_KEY and EVIDENCY_PROJECT_KEY/,
  );
  assert.throws(
    () =>
      resolveEvidencyConfig({
        EVIDENCY_MODE: "sandbox",
        EVIDENCY_API_KEY: "secret",
        EVIDENCY_PROJECT_KEY: "project-a",
        EVIDENCY_API_BASE_URL: "https://example.test",
      }),
    /official Evidency sandbox origin/,
  );
  const config = resolveEvidencyConfig({
    EVIDENCY_MODE: "sandbox",
    EVIDENCY_API_KEY: "secret",
    EVIDENCY_PROJECT_KEY: "project-a",
  });
  assert.equal(config.baseUrl, "https://api-sandbox.evidency.io");
  assert.equal(config.timeoutMs, 12_000);
});

test("the sandbox adapter sends only the evidence digest and labels the token test-only", async () => {
  let request;
  const service = createEvidencyTimestampService(
    {
      mode: "sandbox",
      apiKey: "secret",
      projectKey: "project-a",
      baseUrl: "https://api-sandbox.evidency.io",
      timeoutMs: 1_000,
    },
    {
      fetchImpl: async (url, options) => {
        request = { url, options };
        return new Response(
          JSON.stringify({
            status: 0,
            hashAlgorithm: "2.16.840.1.101.3.4.2.1",
            hashedMessage: digest,
            serialNumber: fixture.serialNumber,
            timestamp: fixture.certifiedAt,
            token,
            tsaPolicyId: fixture.tsaPolicyId,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
      now: () => Date.parse("2026-08-12T19:32:00.000Z"),
    },
  );
  const proof = await service.issueTimestamp({
    recordId: "SR-1",
    evidenceDigest: digest,
  });

  assert.match(request.url, /\/v3\/projects\/project-a\/timestamp$/);
  assert.equal(request.options.headers["x-api-key"], "secret");
  assert.equal(request.options.headers["user-agent"], "SiteSealed/1.4-alpha.6");
  assert.deepEqual(JSON.parse(request.options.body), {
    hashAlgorithm: "SHA256",
    hashedMessage: digest,
    certReq: true,
  });
  assert.equal(JSON.stringify(request).includes("original"), false);
  assert.equal(proof.state, "SANDBOX_TOKEN_ISSUED");
  assert.equal(proof.legalUse, false);
  assert.equal(proof.qualificationStatus, "TEST_ONLY_NOT_QUALIFIED");
  assert.equal(proof.signatureVerification, "VALID");
  assert.equal(
    proof.certificateChainVerification,
    "VALID_TO_PINNED_SANDBOX_ROOT",
  );
  assert.equal(proof.signingCertificateVerification, "ESSCERTIDV2_MATCH");
  assert.equal(proof.revocationVerification, "NOT_CHECKED");
  assert.equal(proof.certifiedAt, fixture.certifiedAt);
  assert.equal(proof.tokenSha256, fixture.tokenSha256);
});

test("the adapter keeps compatibility with the legacy Unix-millisecond timestamp", async () => {
  const issuedAt = Date.parse("2026-08-12T18:00:00.000Z");
  assert.equal(
    normalizeEvidencyTimestamp(issuedAt, { nowMs: issuedAt + 1_000 }),
    "2026-08-12T18:00:00.000Z",
  );
  assert.equal(
    normalizeEvidencyTimestamp(String(issuedAt), { nowMs: issuedAt + 1_000 }),
    "2026-08-12T18:00:00.000Z",
  );
});

test("the adapter rejects malformed, stale and future Evidency timestamps", () => {
  const nowMs = Date.parse("2026-08-12T18:00:00.000Z");
  assert.throws(
    () => normalizeEvidencyTimestamp("not-a-date", { nowMs }),
    /invalid timestamp value/,
  );
  assert.throws(
    () =>
      normalizeEvidencyTimestamp("2026-08-10T18:00:00Z", { nowMs }),
    /invalid timestamp value/,
  );
  assert.throws(
    () =>
      normalizeEvidencyTimestamp("2026-08-12T19:00:00Z", { nowMs }),
    /invalid timestamp value/,
  );
});

test("the adapter rejects a token response bound to another digest", async () => {
  const service = createEvidencyTimestampService(
    {
      mode: "sandbox",
      apiKey: "secret",
      projectKey: "project-a",
      baseUrl: "https://api-sandbox.evidency.io",
      timeoutMs: 1_000,
    },
    {
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            status: 0,
            hashAlgorithm: "SHA256",
            hashedMessage: "b".repeat(64),
            serialNumber: fixture.serialNumber,
            timestamp: Date.now(),
            token,
            tsaPolicyId: fixture.tsaPolicyId,
          }),
          { status: 200 },
        ),
    },
  );
  await assert.rejects(
    service.issueTimestamp({ recordId: "SR-1", evidenceDigest: digest }),
    /different digest/,
  );
});
