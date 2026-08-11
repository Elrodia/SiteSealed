import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createMysqlRecordStore,
  mapRecordRow,
  resolveDatabaseConfig,
} from "./database.js";

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

test("database rows map to the public dual-rail record shape", () => {
  const record = mapRecordRow({
    record_id: "SR-2026-08-0147-A3",
    specimen_payload: {
      classification: "Live capture",
      project: "Riverside Business Park",
      description: "Standing water",
      file: "IMG_2417.JPG",
      captureMode: "In-app camera only",
      capturedAt: "2026-08-10T11:47:03.000Z",
      position: "50.6412 N, 5.5710 E",
    },
    certified_at: new Date("2026-08-10T11:47:09.000Z"),
    record_sha256:
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    manifest_sha256:
      "7f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a09",
    is_specimen: 1,
    qualified_provider: "Simulated QTSP",
    token_reference: "RFC 3161 specimen",
    qualified_status: "simulated",
    chain_name: "Ethereum mainnet (simulated)",
    block_number: 21_904_553,
    transaction_hash: "0xspecimen",
    merkle_root: "specimen-root",
    batch_size: 1024,
    chain_status: "simulated",
  });

  assert.equal(record.specimen, true);
  assert.equal(record.qualifiedAt, "2026-08-10T11:47:09.000Z");
  assert.equal(record.project, "Riverside Business Park");
  assert.equal(record.chainRail.block, "21,904,553");
  assert.equal(record.chainRail.batchSize, 1024);
});

test("record lookup is parameterized and requires both proof rails", async () => {
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
  const record = await store.findById("SR-2026-08-0147-A3");

  assert.equal(record, null);
  assert.match(capturedSql, /INNER JOIN qualified_timestamp_proofs/);
  assert.match(capturedSql, /INNER JOIN public_chain_proofs/);
  assert.match(capturedSql, /records\.record_id = \?/);
  assert.deepEqual(capturedParameters, ["SR-2026-08-0147-A3"]);
});
