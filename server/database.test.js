import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createMysqlRecordStore,
  mapRecordRow,
  resolveDatabaseConfig,
} from "./database.js";
import { validateSealRequest } from "./records.js";

const submissionId = "123e4567-e89b-42d3-a456-426614174000";
const storageCipherSha256 = "d".repeat(64);

function encryptedObject() {
  return {
    version: 1,
    storageClass: "PRIVATE_CLIENT_ENCRYPTED_ORIGINAL",
    objectKey: `sealed/v1.2/${submissionId}/dd/${storageCipherSha256}.ssenc`,
    algorithm: "AES-256-GCM",
    iv: Buffer.alloc(12, 3).toString("base64"),
    ciphertextSha256: storageCipherSha256,
    ciphertextBytes: 32,
    plaintextBytes: 16,
    recoveryTokenSha256: "e".repeat(64),
  };
}

test("Railway MYSQL_URL is parsed without exposing credentials", () => {
  const config = resolveDatabaseConfig({
    DATABASE_MODE: "required",
    MYSQL_URL:
      "mysql://site_user:p%40ssword@mysql.railway.internal:3306/railway",
    MYSQL_CONNECTION_LIMIT: "7",
  });

  assert.deepEqual(config, {
    host: "mysql.railway.internal",
    port: 3306,
    user: "site_user",
    password: "p@ssword",
    database: "railway",
    connectionLimit: 7,
  });
});

test("optional mode permits local development without MySQL", () => {
  assert.equal(resolveDatabaseConfig({ DATABASE_MODE: "optional" }), null);
});

test("required mode refuses to start without a MySQL reference", () => {
  assert.throws(
    () => resolveDatabaseConfig({ DATABASE_MODE: "required" }),
    /MYSQL_URL is not configured/,
  );
});

test("database rows map an unqualified real receipt without inventing rails", () => {
  const record = mapRecordRow({
    record_id: "SR-20260811-ABCDEF0123456789ABCDEF01",
    record_sha256: "a".repeat(64),
    manifest_sha256: "b".repeat(64),
    manifest_encryption: "AES-256-GCM / client-held key",
    record_class: "IMPORTED_FILE",
    proof_level: "DEVELOPMENT_RECEIPT",
    receipt_sha256: "c".repeat(64),
    storage_provider: "S3_PRIVATE_BUCKET",
    storage_object_key: encryptedObject().objectKey,
    storage_cipher_sha256: storageCipherSha256,
    storage_cipher_iv: encryptedObject().iv,
    storage_cipher_bytes: 32,
    storage_plaintext_bytes: 16,
    storage_recovery_token_sha256: "e".repeat(64),
    storage_status: "STORED_ENCRYPTED",
    is_specimen: 0,
    created_at: new Date("2026-08-11T21:00:00.000Z"),
  });

  assert.equal(record.specimen, false);
  assert.equal(record.receivedAt, "2026-08-11T21:00:00.000Z");
  assert.equal(record.receiptSha256, "c".repeat(64));
  assert.equal(record.storage.state, "STORED_ENCRYPTED");
  assert.equal(record.storage.provider, "S3_PRIVATE_BUCKET");
  assert.equal(record.qualifiedRail.state, "NOT_ISSUED");
  assert.equal(record.chainRail.state, "NOT_ANCHORED");
});

test("record lookup is parameterized and uses optional proof joins", async () => {
  let capturedSql = "";
  let capturedParameters = [];
  const pool = {
    async execute(sql, parameters) {
      capturedSql = sql;
      capturedParameters = parameters;
      return [[], []];
    },
  };

  const store = createMysqlRecordStore(pool);
  const record = await store.findById("SR-20260811-ABCDEF0123456789ABCDEF01");

  assert.equal(record, null);
  assert.match(capturedSql, /LEFT JOIN qualified_timestamp_proofs/);
  assert.match(capturedSql, /LEFT JOIN public_chain_proofs/);
  assert.match(capturedSql, /records\.record_id = \?/);
  assert.deepEqual(capturedParameters, ["SR-20260811-ABCDEF0123456789ABCDEF01"]);
});

test("MySQL receipt creation stores digests, encrypted manifest and private S3 reference", async () => {
  const calls = [];
  const pool = {
    async execute(sql, parameters) {
      calls.push({ sql, parameters });
      if (sql.includes("WHERE records.submission_id")) return [[], []];
      if (sql.startsWith("INSERT INTO sealed_records")) {
        return [{ affectedRows: 1 }, []];
      }
      throw new Error(`Unexpected SQL: ${sql}`);
    },
  };
  const input = validateSealRequest({
    submissionId,
    protocolVersion: "1.2",
    recordClass: "IMPORTED_FILE",
    recordSha256: "a".repeat(64),
    manifestSha256: "b".repeat(64),
    encryptedManifest: {
      version: 1,
      algorithm: "AES-256-GCM",
      iv: Buffer.alloc(12, 1).toString("base64"),
      ciphertext: Buffer.alloc(24, 2).toString("base64"),
    },
    encryptedObject: encryptedObject(),
  });

  const result = await createMysqlRecordStore(pool).create(input);
  assert.equal(result.created, true);
  assert.equal(result.record.proofLevel, "DEVELOPMENT_RECEIPT");
  const insert = calls.find((call) => call.sql.startsWith("INSERT INTO sealed_records"));
  assert.ok(insert);
  assert.equal(insert.parameters.includes(input.recordSha256), true);
  assert.equal(insert.parameters.some((value) => Buffer.isBuffer(value)), true);
  assert.equal(insert.parameters.some((value) => value === "DEVELOPMENT_RECEIPT"), true);
  assert.equal(insert.parameters.includes(encryptedObject().objectKey), true);
  assert.equal(insert.parameters.includes(storageCipherSha256), true);
  assert.equal(insert.parameters.includes("STORED_ENCRYPTED"), true);
  assert.equal(insert.parameters.some((value) => value === "original bytes"), false);
});
