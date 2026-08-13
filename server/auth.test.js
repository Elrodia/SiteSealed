import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createGoogleIdentityService,
  resolveGoogleAuthConfig,
  safeCsrfEqual,
  verifyGoogleDoubleSubmitCsrf,
} from "./auth.js";

const CLIENT_ID = "123456789-alpha9.apps.googleusercontent.com";

test("missing Google configuration keeps the server online with sign-in disabled", () => {
  const config = resolveGoogleAuthConfig({});
  assert.equal(config.configured, false);
  assert.equal(config.clientId, null);
  assert.equal(config.loginUri, null);
  assert.equal(config.sessionTtlHours, 168);
});

test("Google configuration derives an exact redirect URI and secure cookies", () => {
  const config = resolveGoogleAuthConfig({
    GOOGLE_OAUTH_CLIENT_ID: CLIENT_ID,
    PUBLIC_BASE_URL: "https://app.sitesealed.com/path-is-ignored",
    AUTH_SESSION_TTL_HOURS: "24",
  });
  assert.equal(config.configured, true);
  assert.equal(config.publicOrigin, "https://app.sitesealed.com");
  assert.equal(
    config.loginUri,
    "https://app.sitesealed.com/api/auth/google/callback",
  );
  assert.equal(config.secureCookies, true);
  assert.equal(config.sessionTtlMs, 24 * 60 * 60 * 1000);
});

test("invalid Google identifiers disable sign-in without crashing the service", () => {
  const config = resolveGoogleAuthConfig({
    GOOGLE_OAUTH_CLIENT_ID: "not-a-google-client",
    PUBLIC_BASE_URL: "https://app.sitesealed.com",
  });
  assert.equal(config.configured, false);
  assert.match(config.configurationError, /valid Google Web application client ID/);
});

test("the verified Google subject becomes a domain-separated local principal", async () => {
  const config = resolveGoogleAuthConfig({
    GOOGLE_OAUTH_CLIENT_ID: CLIENT_ID,
    PUBLIC_BASE_URL: "https://app.sitesealed.com",
  });
  const oauthClient = {
    async verifyIdToken({ idToken, audience }) {
      assert.equal(idToken, "header.payload.signature");
      assert.equal(audience, CLIENT_ID);
      return {
        getPayload() {
          return {
            iss: "https://accounts.google.com",
            aud: CLIENT_ID,
            sub: "123456789012345678901",
            email: "Owner@Example.test",
            email_verified: true,
            name: "SiteSealed Owner",
          };
        },
      };
    },
  };
  const service = createGoogleIdentityService(config, { oauthClient });
  const user = await service.verifyCredential("header.payload.signature");
  assert.match(user.id, /^[a-f0-9]{64}$/);
  assert.equal(user.provider, "GOOGLE");
  assert.equal(user.email, "owner@example.test");
  assert.equal(user.name, "SiteSealed Owner");
  assert.equal(JSON.stringify(user).includes("123456789012345678901"), false);
});

test("unverified or wrongly issued Google claims are rejected", async () => {
  const config = resolveGoogleAuthConfig({
    GOOGLE_OAUTH_CLIENT_ID: CLIENT_ID,
    PUBLIC_BASE_URL: "https://app.sitesealed.com",
  });
  const service = createGoogleIdentityService(config, {
    oauthClient: {
      async verifyIdToken() {
        return {
          getPayload() {
            return {
              iss: "https://attacker.invalid",
              aud: CLIENT_ID,
              sub: "123456789012345678901",
              email: "owner@example.test",
              email_verified: true,
            };
          },
        };
      },
    },
  });
  await assert.rejects(
    service.verifyCredential("header.payload.signature"),
    (error) => error?.status === 401 && error?.code === "GOOGLE_ID_TOKEN_REJECTED",
  );
});

test("Google and application CSRF comparisons reject mismatch and empty values", () => {
  verifyGoogleDoubleSubmitCsrf(
    "other=value; g_csrf_token=matching-token",
    "matching-token",
  );
  assert.throws(
    () =>
      verifyGoogleDoubleSubmitCsrf(
        "g_csrf_token=cookie-token",
        "body-token",
      ),
    (error) => error?.status === 400 && error?.code === "GOOGLE_CSRF_REJECTED",
  );
  assert.equal(safeCsrfEqual("token", "token"), true);
  assert.equal(safeCsrfEqual("token", "different"), false);
  assert.equal(safeCsrfEqual("", ""), false);
});
