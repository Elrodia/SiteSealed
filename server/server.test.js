import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createApp } from "./server.js";

let server;
let baseUrl;

before(async () => {
  const app = createApp();
  await new Promise((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

test("health endpoint reports a ready service", async () => {
  const response = await fetch(`${baseUrl}/api/health`);
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.ok, true);
  assert.equal(payload.service, "sitesealed");
  assert.equal(payload.version, "1.1.0");
  assert.deepEqual(payload.database, {
    mode: "memory",
    status: "not_configured",
    persistent: false,
  });
});

test("specimen verification returns both proof rails", async () => {
  const response = await fetch(`${baseUrl}/api/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ recordId: "sr-2026-08-0147-a3" }),
  });
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.specimen, true);
  assert.equal(payload.record.recordId, "SR-2026-08-0147-A3");
  assert.ok(payload.record.qualifiedRail);
  assert.ok(payload.record.chainRail);
});

test("unknown records fail honestly", async () => {
  const response = await fetch(`${baseUrl}/api/verify/UNKNOWN-RECORD`);
  assert.equal(response.status, 404);
  const payload = await response.json();
  assert.equal(payload.ok, false);
  assert.equal(payload.code, "RECORD_NOT_FOUND");
});

test("the production server serves the React application", async () => {
  const response = await fetch(`${baseUrl}/`);
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /SiteSealed/);
  assert.match(html, /id="root"/);
});

test("production assets and the specimen PDF are served", async () => {
  const [iconResponse, reportResponse] = await Promise.all([
    fetch(`${baseUrl}/icon-192.svg`),
    fetch(`${baseUrl}/documents/SiteSealed_EvidenceReport_SPECIMEN.pdf`),
  ]);
  assert.equal(iconResponse.status, 200);
  assert.match(iconResponse.headers.get("content-type"), /image\/svg\+xml/);
  assert.equal(reportResponse.status, 200);
  assert.match(reportResponse.headers.get("content-type"), /application\/pdf/);
});

test("malformed JSON receives a controlled client error", async () => {
  const response = await fetch(`${baseUrl}/api/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{not-json}",
  });
  assert.equal(response.status, 400);
  const payload = await response.json();
  assert.equal(payload.code, "INVALID_JSON");
});
