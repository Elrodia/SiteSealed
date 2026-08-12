import { createHash } from "node:crypto";

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
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

export function resolveEvidencyConfig(environment = process.env) {
  const mode = String(environment.EVIDENCY_MODE ?? "disabled")
    .trim()
    .toLowerCase();
  if (mode === "disabled") return null;
  if (mode !== "sandbox") {
    throw new Error('EVIDENCY_MODE must be either "disabled" or "sandbox" in v1.4-alpha.3.');
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
  { fetchImpl = globalThis.fetch } = {},
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
              "user-agent": "SiteSealed/1.4-alpha.3",
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
      const certifiedAtMs = Number(payload.timestamp);
      if (!Number.isSafeInteger(certifiedAtMs) || certifiedAtMs <= 0) {
        throw new Error("Evidency returned an invalid timestamp value.");
      }
      const token = canonicalBase64(payload.token);
      const serialNumber = String(payload.serialNumber ?? "").trim();
      const tsaPolicyId = String(payload.tsaPolicyId ?? "").trim();
      if (!serialNumber || !tsaPolicyId) {
        throw new Error("Evidency returned an incomplete timestamp response.");
      }

      return {
        state: "SANDBOX_TOKEN_ISSUED",
        provider: "Evidency",
        environment: "SANDBOX",
        legalUse: false,
        qualificationStatus: "TEST_ONLY_NOT_QUALIFIED",
        hashAlgorithm: "SHA256",
        hashedMessage: digest,
        serialNumber,
        certifiedAt: new Date(certifiedAtMs).toISOString(),
        tokenBase64: token.encoded,
        tokenSha256: createHash("sha256").update(token.bytes).digest("hex"),
        tsaPolicyId,
        providerStatus: 0,
        responseValidation: "STATUS_ALGORITHM_AND_DIGEST_BOUND",
        signatureVerification: "NOT_INDEPENDENTLY_VERIFIED",
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
        signatureVerification: "ON_EXPORTED_TOKEN_WITH_OPENSSL",
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
