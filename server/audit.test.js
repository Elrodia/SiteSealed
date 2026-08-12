import assert from "node:assert/strict";
import { test } from "node:test";
import {
  buildAuditEvent,
  createMemoryAuditStore,
  receiptAuditPayload,
  resolvePostgresConfig,
  verifyAuditEvent,
} from "./audit.js";

function record(overrides = {}) {
  return {
    recordId: "SR-20260812-AAAAAAAAAAAAAAAAAAAAAAAA",
    specimen: false,
    recordClass: "IMPORTED_FILE",
    proofLevel: "DEVELOPMENT_RECEIPT",
    sha256: "a".repeat(64),
    manifestSha256: "b".repeat(64),
    receiptSha256: "c".repeat(64),
    storage: { ciphertextSha256: "d".repeat(64) },
    qualifiedRail: { state: "NOT_ISSUED" },
    chainRail: { state: "NOT_ANCHORED" },
    ...overrides,
  };
}

test("PostgreSQL configuration accepts Railway DATABASE_URL and enforces required mode", () => {
  assert.equal(resolvePostgresConfig({ DATABASE_MODE: "optional" }), null);
  assert.throws(
    () => resolvePostgresConfig({ DATABASE_MODE: "required" }),
    /DATABASE_URL is not configured/,
  );
  const config = resolvePostgresConfig({
    DATABASE_MODE: "required",
    DATABASE_URL: "postgresql://user:secret@postgres.railway.internal:5432/railway",
  });
  assert.equal(config.connectionLimit, 5);
  assert.match(config.url, /^postgresql:\/\//);
  assert.throws(
    () =>
      resolvePostgresConfig({
        DATABASE_MODE: "required",
        DATABASE_URL: "mysql://user:secret@host/database",
      }),
    /postgres:\/\/ or postgresql:\/\//,
  );
});

test("audit event hashes bind payload, order and time", () => {
  const event = buildAuditEvent({
    eventId: "123e4567-e89b-42d3-a456-426614174000",
    recordId: "SR-20260812-AAAAAAAAAAAAAAAAAAAAAAAA",
    payload: { receiptSha256: "a".repeat(64) },
    previousEventSha256: "b".repeat(64),
    recordedAt: "2026-08-12T12:00:00.000Z",
  });
  assert.equal(verifyAuditEvent(event), true);
  assert.match(event.payloadSha256, /^[a-f0-9]{64}$/);
  assert.match(event.eventSha256, /^[a-f0-9]{64}$/);
  assert.equal(
    verifyAuditEvent({ ...event, payload: { receiptSha256: "f".repeat(64) } }),
    false,
  );
  assert.equal(
    verifyAuditEvent({ ...event, previousEventSha256: "e".repeat(64) }),
    false,
  );
});

test("memory audit is append-only, hash-chained and idempotent", async () => {
  const store = createMemoryAuditStore();
  const firstRecord = record();
  const first = await store.appendReceipt(firstRecord);
  const reused = await store.appendReceipt(firstRecord);
  const second = await store.appendReceipt(
    record({ recordId: "SR-20260812-BBBBBBBBBBBBBBBBBBBBBBBB" }),
  );

  assert.equal(first.created, true);
  assert.equal(reused.created, false);
  assert.equal(reused.audit.event.eventSha256, first.audit.event.eventSha256);
  assert.equal(second.audit.event.previousEventSha256, first.audit.event.eventSha256);
  assert.equal(verifyAuditEvent(second.audit.event), true);
  assert.equal(
    (await store.findByRecordId(firstRecord.recordId)).event.sequence,
    "1",
  );
  assert.deepEqual(receiptAuditPayload(firstRecord), first.audit.event.payload);

  await assert.rejects(
    store.appendReceipt(record({ sha256: "f".repeat(64) })),
    (error) => error.code === "AUDIT_EVENT_CONFLICT" && error.status === 409,
  );
});

