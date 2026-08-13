import { verifyRfc3161Token } from "./rfc3161.js";

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const ISO_8601_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const MAX_TIMESTAMP_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_TIMESTAMP_FUTURE_SKEW_MS = 10 * 60 * 1000;
const SHA256_IDENTIFIERS = new Set([
  "SHA256",
  "SHA-256",
  "2.16.840.1.101.3.4.2.1",
]);

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function canonicalBase64(value) {
  const encoded = String(value ?? "").trim();
  if (!encoded || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
    throw new Error("Evidency returned an invalid Base64 timestamp token.");
  }
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length < 16 || bytes.toString("base64") !== encoded) {
    throw new Error("Evidency returned an invalid Base64 timestamp token.");
  }
  return { encoded, bytes };
}

export function normalizeEvidencyTimestamp(value, { nowMs = Date.now() } = {}) {
  let timestampMs;

  if (typeof value === "number") {
    timestampMs = value;
  } else if (typeof value === "string") {
    const timestamp = value.trim();
    if (ISO_8601_TIMESTAMP_PATTERN.test(timestamp)) {
      timestampMs = Date.parse(timestamp);
    } else if (/^\d+$/.test(timestamp)) {
      timestampMs = Number(timestamp);
    } else {
      throw new Error("Evidency returned an invalid timestamp value.");
    }
  } else {
    throw new Error("Evidency returned an invalid timestamp value.");
  }

  const referenceMs = Number(nowMs);
  if (
    !Number.isSafeInteger(timestampMs) ||
    timestampMs <= 0 ||
    !Number.isSafeInteger(referenceMs) ||
    timestampMs < referenceMs - MAX_TIMESTAMP_AGE_MS ||
    timestampMs > referenceMs + MAX_TIMESTAMP_FUTURE_SKEW_MS
  ) {
    throw new Error("Evidency returned an invalid timestamp value.");
  }

  return new Date(timestampMs).toISOString();
}

export function resolveEvidencyConfig(environment = process.env) {
  const mode = String(environment.EVIDENCY_MODE ?? "disabled")
    .trim()
    .toLowerCase();
  if (mode === "disabled") return null;
  if (mode !== "sandbox") {
    throw new Error('EVIDENCY_MODE must be either "disabled" or "sandbox" in v1.4-alpha.10.1.');
  }

  const apiKey = String(environment.EVIDENCY_API_KEY ?? "").trim();
  const projectKey = String(environment.EVIDENCY_PROJECT_KEY ?? "").trim();
  const baseUrlValue = String(
    environment.EVIDENCY_API_BASE_URL ?? "https://api-sandbox.evidency.io",
  ).trim();
  if (!apiKey || !projectKey) {
    throw new Error(
      "Evidency sandbox mode requires EVIDENCY_API_KEY and EVIDENCY_PROJECT_KEY.",
    );
  }

  let baseUrl;
  try {
    baseUrl = new URL(baseUrlValue);
  } catch {
    throw new Error("EVIDENCY_API_BASE_URL must be a valid HTTPS URL.");
  }
  if (baseUrl.protocol !== "https:") {
    throw new Error("EVIDENCY_API_BASE_URL must use HTTPS.");
  }
  if (baseUrl.origin !== "https://api-sandbox.evidency.io") {
    throw new Error(
      "EVIDENCY_API_BASE_URL must be the official Evidency sandbox origin.",
    );
  }

  return {
    mode,
    apiKey,
    projectKey,
    baseUrl: baseUrl.origin,
    timeoutMs: positiveInteger(environment.EVIDENCY_TIMEOUT_MS, 12_000),
  };
}

export function createDisabledTimestampService() {
  return {
    mode: "disabled",
    configured: false,
    environment: null,
    legalUse: false,
    async issueTimestamp() {
      return null;
    },
    async healthCheck() {
      return {
        mode: "disabled",
        status: "not_configured",
        provider: "Evidency",
        environment: "SANDBOX",
        legalUse: false,
      };
    },
    async close() {},
  };
}

export function createEvidencyTimestampService(
  config,
  {
    fetchImpl = globalThis.fetch,
    now = Date.now,
    tokenVerifier = verifyRfc3161Token,
  } = {},
) {
  if (!config || config.mode !== "sandbox") {
    throw new Error("A valid Evidency sandbox configuration is required.");
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("A Fetch implementation is required for Evidency.");
  }

  return {
    mode: "evidency",
    configured: true,
    environment: "SANDBOX",
    legalUse: false,

    async issueTimestamp({ recordId, evidenceDigest }) {
      const digest = String(evidenceDigest ?? "").trim().toLowerCase();
      if (!SHA256_PATTERN.test(digest)) {
        throw new Error("evidenceDigest must be a SHA-256 digest.");
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), config.timeoutMs);
      timeout.unref?.();
      let response;
      try {
        response = await fetchImpl(
          `${config.baseUrl}/v3/projects/${encodeURIComponent(config.projectKey)}/timestamp`,
          {
            method: "POST",
            headers: {
              "content-type": "application/json",
              accept: "application/json",
              "x-api-key": config.apiKey,
              "user-agent": "SiteSealed/1.4-alpha.10.1",
            },
            body: JSON.stringify({
              hashAlgorithm: "SHA256",
              hashedMessage: digest,
              certReq: true,
            }),
            signal: controller.signal,
          },
        );
      } catch (error) {
        if (error?.name === "AbortError") {
          throw new Error("Evidency sandbox did not respond before the timeout.");
        }
        throw new Error(`Evidency sandbox request failed: ${error.message}`);
      } finally {
        clearTimeout(timeout);
      }

      const responseText = await response.text();
      if (responseText.length > 2 * 1024 * 1024) {
        throw new Error("Evidency sandbox returned an unexpectedly large response.");
      }
      let payload;
      try {
        payload = JSON.parse(responseText);
      } catch {
        throw new Error(
          `Evidency sandbox returned unreadable JSON (HTTP ${response.status}).`,
        );
      }
      if (!response.ok) {
        const providerMessage = String(
          payload?.message ?? payload?.error ?? `HTTP ${response.status}`,
        ).slice(0, 240);
        throw new Error(`Evidency sandbox rejected the timestamp request: ${providerMessage}`);
      }
      if (Number(payload.status) !== 0) {
        throw new Error(`Evidency returned timestamp status ${payload.status}.`);
      }
      const returnedDigest = String(payload.hashedMessage ?? "")
        .trim()
        .toLowerCase();
      if (returnedDigest !== digest) {
        throw new Error("Evidency returned a timestamp bound to a different digest.");
      }
      const algorithm = String(payload.hashAlgorithm ?? "").toUpperCase();
      if (!SHA256_IDENTIFIERS.has(algorithm)) {
        throw new Error("Evidency returned an unexpected hash algorithm.");
      }
      const certifiedAt = normalizeEvidencyTimestamp(payload.timestamp, {
        nowMs: now(),
      });
      const token = canonicalBase64(payload.token);
      const serialNumber = String(payload.serialNumber ?? "").trim();
      const tsaPolicyId = String(payload.tsaPolicyId ?? "").trim();
      if (!serialNumber || !tsaPolicyId) {
        throw new Error("Evidency returned an incomplete timestamp response.");
      }

      let independentVerification;
      try {
        independentVerification = await tokenVerifier({
          token: token.bytes,
          expectedDigest: digest,
          expectedSerialNumber: serialNumber,
          expectedCertifiedAt: certifiedAt,
          expectedPolicyId: tsaPolicyId,
        });
      } catch (error) {
        const code = String(error?.code ?? "RFC3161_VERIFICATION_FAILED");
        throw new Error(
          `Evidency returned a token that failed independent RFC 3161 verification (${code}).`,
        );
      }

      return {
        state: "SANDBOX_TOKEN_ISSUED",
        provider: "Evidency",
        environment: "SANDBOX",
        legalUse: false,
        qualificationStatus: "TEST_ONLY_NOT_QUALIFIED",
        hashAlgorithm: independentVerification.hashAlgorithm,
        hashedMessage: independentVerification.hashedMessage,
        serialNumber: independentVerification.serialNumber,
        certifiedAt: independentVerification.certifiedAt,
        tokenBase64: token.encoded,
        tokenSha256: independentVerification.tokenSha256,
        tsaPolicyId: independentVerification.tsaPolicyId,
        providerStatus: 0,
        responseValidation: independentVerification.responseValidation,
        signatureVerification: independentVerification.signatureVerification,
        certificateChainVerification:
          independentVerification.certificateChainVerification,
        signingCertificateVerification:
          independentVerification.signingCertificateVerification,
        signingCertificateHashAlgorithm:
          independentVerification.signingCertificateHashAlgorithm,
        cmsAlgorithmProtection:
          independentVerification.cmsAlgorithmProtection,
        revocationVerification:
          independentVerification.revocationVerification,
        validatorVersion: independentVerification.validatorVersion,
        cmsDigestAlgorithm: independentVerification.cmsDigestAlgorithm,
        cmsSignatureAlgorithm: independentVerification.cmsSignatureAlgorithm,
        signerCertificateSha256:
          independentVerification.signerCertificateSha256,
        signerCertificateSubject:
          independentVerification.signerCertificateSubject,
        signerCertificateIssuer:
          independentVerification.signerCertificateIssuer,
        signerCertificateValidFrom:
          independentVerification.signerCertificateValidFrom,
        signerCertificateValidTo:
          independentVerification.signerCertificateValidTo,
        trustAnchorSha256: independentVerification.trustAnchorSha256,
        trustAnchorSubject: independentVerification.trustAnchorSubject,
        certificatePathLength:
          independentVerification.certificatePathLength,
        recordId,
      };
    },

    async healthCheck() {
      return {
        mode: "evidency",
        status: "configured",
        provider: "Evidency",
        environment: "SANDBOX",
        legalUse: false,
        endpoint: "api-sandbox.evidency.io",
        signatureVerification: "REQUIRED_BEFORE_STORAGE",
        certificateChainVerification: "PINNED_SANDBOX_ROOT_REQUIRED",
        validatorVersion: "SITESEALED_RFC3161_VALIDATOR_V1",
        revocationVerification: "NOT_CHECKED",
      };
    },

    async close() {},
  };
}

export function createEvidencyTimestampServiceFromEnv(
  environment = process.env,
  options = {},
) {
  const config = resolveEvidencyConfig(environment);
  return config
    ? createEvidencyTimestampService(config, options)
    : createDisabledTimestampService();
}
