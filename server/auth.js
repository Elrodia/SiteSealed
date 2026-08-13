import { createHash, timingSafeEqual } from "node:crypto";
import { OAuth2Client } from "google-auth-library";
import { ApiError } from "./records.js";

const GOOGLE_ISSUERS = new Set([
  "accounts.google.com",
  "https://accounts.google.com",
]);
const GOOGLE_CLIENT_ID_PATTERN =
  /^[0-9]+-[a-z0-9_-]+\.apps\.googleusercontent\.com$/i;
const MAXIMUM_GOOGLE_CREDENTIAL_BYTES = 16 * 1024;

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

function normalizePublicOrigin(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return null;
  try {
    const url = new URL(raw);
    if (!["https:", "http:"].includes(url.protocol)) return null;
    if (url.username || url.password || url.search || url.hash) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function principalId(subject) {
  return createHash("sha256")
    .update("sitesealed:v1.4:google-subject\0", "utf8")
    .update(subject, "utf8")
    .digest("hex");
}

function safeDisplayText(value, maximum) {
  const text = String(value ?? "").trim().replace(/[\u0000-\u001f\u007f]/g, "");
  return text.slice(0, maximum);
}

function cookieValue(cookieHeader, name) {
  const cookies = String(cookieHeader ?? "").split(";");
  for (const cookie of cookies) {
    const separator = cookie.indexOf("=");
    if (separator < 1) continue;
    if (cookie.slice(0, separator).trim() !== name) continue;
    const encoded = cookie.slice(separator + 1).trim();
    try {
      return decodeURIComponent(encoded);
    } catch {
      return null;
    }
  }
  return null;
}

function safeTextEqual(left, right, maximumBytes = 512) {
  const leftBuffer = Buffer.from(String(left ?? ""), "utf8");
  const rightBuffer = Buffer.from(String(right ?? ""), "utf8");
  return (
    leftBuffer.length > 0 &&
    leftBuffer.length <= maximumBytes &&
    leftBuffer.length === rightBuffer.length &&
    timingSafeEqual(leftBuffer, rightBuffer)
  );
}

export function resolveGoogleAuthConfig(environment = process.env) {
  const clientId = String(environment.GOOGLE_OAUTH_CLIENT_ID ?? "").trim();
  const publicOrigin = normalizePublicOrigin(environment.PUBLIC_BASE_URL);
  const sessionTtlHours = boundedInteger(
    environment.AUTH_SESSION_TTL_HOURS,
    168,
    1,
    720,
    "AUTH_SESSION_TTL_HOURS",
  );

  let configurationError = null;
  if (clientId && !GOOGLE_CLIENT_ID_PATTERN.test(clientId)) {
    configurationError =
      "GOOGLE_OAUTH_CLIENT_ID is not a valid Google Web application client ID.";
  } else if (clientId && !publicOrigin) {
    configurationError =
      "PUBLIC_BASE_URL must be configured before Google sign-in can be enabled.";
  } else if (
    clientId &&
    publicOrigin &&
    !publicOrigin.startsWith("https://") &&
    !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicOrigin)
  ) {
    configurationError =
      "Google sign-in requires HTTPS except on localhost.";
  }

  const configured = Boolean(clientId && publicOrigin && !configurationError);
  return {
    configured,
    configurationError,
    clientId: configured ? clientId : null,
    publicOrigin,
    loginUri: configured
      ? `${publicOrigin}/api/auth/google/callback`
      : null,
    secureCookies: Boolean(publicOrigin?.startsWith("https://")),
    sessionTtlMs: sessionTtlHours * 60 * 60 * 1000,
    sessionTtlHours,
  };
}

export function verifyGoogleDoubleSubmitCsrf(cookieHeader, bodyToken) {
  const cookieToken = cookieValue(cookieHeader, "g_csrf_token");
  if (!safeTextEqual(cookieToken, bodyToken)) {
    throw new ApiError(
      400,
      "GOOGLE_CSRF_REJECTED",
      "The Google sign-in response failed its CSRF check.",
    );
  }
}

export function readCookie(cookieHeader, name) {
  return cookieValue(cookieHeader, name);
}

export function safeCsrfEqual(expected, supplied) {
  return safeTextEqual(expected, supplied, 128);
}

export function createGoogleIdentityService(
  config,
  { oauthClient = null } = {},
) {
  const activeConfig = config ?? resolveGoogleAuthConfig({});
  const verifier =
    oauthClient ??
    (activeConfig.configured
      ? new OAuth2Client(activeConfig.clientId)
      : null);

  return {
    mode: "google_oidc",
    ...activeConfig,

    publicConfig() {
      return {
        provider: "GOOGLE",
        configured: activeConfig.configured,
        clientId: activeConfig.clientId,
        loginUri: activeConfig.loginUri,
        configurationError: activeConfig.configurationError,
      };
    },

    async verifyCredential(value) {
      if (!activeConfig.configured || !verifier) {
        throw new ApiError(
          503,
          "GOOGLE_AUTH_NOT_CONFIGURED",
          "Google sign-in is not configured for this deployment.",
        );
      }
      const credential = String(value ?? "").trim();
      if (
        !credential ||
        Buffer.byteLength(credential, "utf8") >
          MAXIMUM_GOOGLE_CREDENTIAL_BYTES ||
        credential.split(".").length !== 3
      ) {
        throw new ApiError(
          401,
          "GOOGLE_ID_TOKEN_REJECTED",
          "The Google identity response is invalid or expired.",
        );
      }

      try {
        const ticket = await verifier.verifyIdToken({
          idToken: credential,
          audience: activeConfig.clientId,
        });
        const payload = ticket.getPayload?.();
        const subject = String(payload?.sub ?? "");
        const email = safeDisplayText(payload?.email, 320).toLowerCase();
        const name = safeDisplayText(payload?.name, 160) || email;
        if (
          !payload ||
          !GOOGLE_ISSUERS.has(payload.iss) ||
          payload.aud !== activeConfig.clientId ||
          payload.email_verified !== true ||
          !/^[A-Za-z0-9_-]{1,255}$/.test(subject) ||
          !email ||
          !email.includes("@")
        ) {
          throw new Error("Google identity claims failed validation.");
        }
        return {
          id: principalId(subject),
          provider: "GOOGLE",
          email,
          name,
        };
      } catch (error) {
        if (error instanceof ApiError) throw error;
        throw new ApiError(
          401,
          "GOOGLE_ID_TOKEN_REJECTED",
          "The Google identity response is invalid or expired.",
        );
      }
    },

    async healthCheck() {
      return {
        mode: "google_oidc",
        status: activeConfig.configured ? "configured" : "not_configured",
        configured: activeConfig.configured,
        sessionStore: "SERVER_COORDINATOR",
        requestedIdentityClaims: ["openid", "email", "profile"],
        googleApiAccess: false,
        configurationError: activeConfig.configurationError,
      };
    },
  };
}

export function createGoogleIdentityServiceFromEnv(environment = process.env) {
  return createGoogleIdentityService(resolveGoogleAuthConfig(environment));
}
