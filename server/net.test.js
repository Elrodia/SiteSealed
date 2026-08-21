import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeRateLimitIdentity } from "./net.js";

test("IPv4 and IPv4-mapped IPv6 normalize to the same identity", () => {
  assert.equal(normalizeRateLimitIdentity("203.0.113.4"), "203.0.113.4");
  assert.equal(
    normalizeRateLimitIdentity("::ffff:203.0.113.4"),
    "203.0.113.4",
  );
  assert.equal(
    normalizeRateLimitIdentity("::ffff:cb00:7104"),
    "203.0.113.4",
  );
});

test("IPv6 identities aggregate by canonical compressed /64", () => {
  assert.equal(
    normalizeRateLimitIdentity("2001:0db8:0001:0002:0000:0000:0000:0001"),
    "2001:db8:1:2::/64",
  );
  assert.equal(
    normalizeRateLimitIdentity("2001:db8:1:2:abcd::9"),
    "2001:db8:1:2::/64",
  );
  assert.notEqual(
    normalizeRateLimitIdentity("2001:db8:1:2::1"),
    normalizeRateLimitIdentity("2001:db8:1:3::1"),
  );
});

test("missing and unparseable addresses share the stable unknown bucket", () => {
  assert.equal(normalizeRateLimitIdentity(undefined), "unknown-client");
  assert.equal(normalizeRateLimitIdentity("not-an-ip"), "unknown-client");
  assert.equal(normalizeRateLimitIdentity(""), "unknown-client");
});
