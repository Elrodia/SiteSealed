import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createEvidencyTimestampService,
  resolveEvidencyConfig,
} from "./evidency.js";

const digest = "a".repeat(64);
const token = Buffer.alloc(64, 7).toString("base64");

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
            serialNumber: "abc123",
            timestamp: Date.parse("2026-08-12T18:00:00.000Z"),
            token,
            tsaPolicyId: "1.3.6.1.4.1.60053.2.1.1.1.1",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    },
  );
  const proof = await service.issueTimestamp({
    recordId: "SR-1",
    evidenceDigest: digest,
  });

  assert.match(request.url, /\/v3\/projects\/project-a\/timestamp$/);
  assert.equal(request.options.headers["x-api-key"], "secret");
  assert.deepEqual(JSON.parse(request.options.body), {
    hashAlgorithm: "SHA256",
    hashedMessage: digest,
    certReq: true,
  });
  assert.equal(JSON.stringify(request).includes("original"), false);
  assert.equal(proof.state, "SANDBOX_TOKEN_ISSUED");
  assert.equal(proof.legalUse, false);
  assert.equal(proof.qualificationStatus, "TEST_ONLY_NOT_QUALIFIED");
  assert.equal(proof.signatureVerification, "NOT_INDEPENDENTLY_VERIFIED");
  assert.match(proof.tokenSha256, /^[a-f0-9]{64}$/);
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
            serialNumber: "abc123",
            timestamp: Date.now(),
            token,
            tsaPolicyId: "1.2.3",
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
