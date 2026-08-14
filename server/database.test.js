import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createMysqlRecordStore,
  mapRecordRow,
  resolveDatabaseConfig,
} from "./database.js";
import { externalProofStatus, validateSealRequest } from "./records.js";

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

test("database rows preserve the additive live-capture context", () => {
  const captureContext = {
    schemaVersion: "sitesealed.capture-context.v1.5-alpha.1",
    workflow: "WEB_CAMERA_CONTEXT_BOUND_ALPHA",
    challengeId: "123e4567-e89b-42d3-a456-426614174000",
    challengeIssuedAt: "2026-08-14T10:00:00.000Z",
    challengeCaptureExpiresAt: "2026-08-14T10:02:00.000Z",
    timeAuthority: "SITESEALED_SERVER_CHALLENGE",
    capturedAt: "2026-08-14T10:00:05.000Z",
    clientClockDeltaMs: 9,
    cameraFacingMode: "environment",
    location: {
      coordinatesManifestBound: true,
      measuredAt: "2026-08-14T10:00:04.000Z",
      accuracyMeters: 8.2,
      attestation: "BROWSER_GEOLOCATION_NOT_HARDWARE_ATTESTED",
    },
    deviceAttestation: "NOT_AVAILABLE_WEB_ALPHA",
    timeAttestation: "SERVER_CHALLENGE_WINDOW",
    account: { provider: "GOOGLE", accountReference: "9".repeat(64) },
  };
  const record = mapRecordRow({
    record_id: "SR-20260814-CONTEXTBOUNDROW",
    record_sha256: "a".repeat(64),
    manifest_sha256: "b".repeat(64),
    manifest_encryption: "AES-256-GCM / client-held key",
    record_class: "LIVE_CAPTURE_WEB",
    proof_level: "DUAL_RAIL_ALPHA_RECEIPT",
    receipt_sha256: "c".repeat(64),
    receipt_version: "1.5-alpha.1",
    capture_context: JSON.stringify(captureContext),
    storage_provider: "S3_PRIVATE_BUCKET",
    storage_object_key: encryptedObject().objectKey,
    storage_cipher_sha256: storageCipherSha256,
    storage_cipher_iv: encryptedObject().iv,
    storage_cipher_bytes: 32,
    storage_plaintext_bytes: 16,
    storage_recovery_token_sha256: "e".repeat(64),
    storage_status: "STORED_ENCRYPTED",
    is_specimen: 0,
    created_at: new Date("2026-08-14T10:00:15.000Z"),
  });

  assert.equal(record.recordClass, "LIVE_CAPTURE_WEB");
  assert.equal(record.capturedAt, captureContext.capturedAt);
  assert.deepEqual(record.captureContext, captureContext);
  assert.deepEqual(record.receipt.captureContext, captureContext);
  assert.equal(record.receipt.schemaVersion, "sitesealed.receipt.v1.5-alpha.1");
});

test("record lookup is parameterized and uses optional proof joins", async () => {
  let capturedSql = "";
  let capturedParameters = [];
  const pool = {
    async query(sql, parameters) {
      capturedSql = sql;
      capturedParameters = parameters;
      return [[], []];
    },
    async execute() {
      throw new Error("Record lookup must avoid COM_STMT_EXECUTE.");
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

test("automatic Ethereum batch recovery never depends on COM_STMT_EXECUTE", async () => {
  let batch = null;
  const members = [];
  const queries = [];
  const actionableStates = new Set([
    "PREPARED",
    "SIGNED",
    "SUBMITTED",
    "CONFIRMED",
  ]);
  const query = async (sql, parameters = []) => {
    queries.push({ sql, parameters });
    const normalized = sql.replace(/\s+/g, " ").trim();
    if (normalized.startsWith("INSERT INTO anchor_batches")) {
      batch = {
        batch_id: parameters[0],
        merkle_protocol: parameters[1],
        merkle_root: parameters[2],
        leaf_count: parameters[3],
        chain_name: "Ethereum mainnet",
        chain_id: 1,
        batch_state: "PREPARED",
        confirmations: 0,
        created_at: new Date("2026-08-13T02:00:00.000Z"),
      };
      return [{ affectedRows: 1 }, []];
    }
    if (normalized.startsWith("INSERT INTO anchor_batch_members")) {
      members.push({
        batch_id: parameters[0],
        record_id: parameters[1],
        leaf_index: parameters[2],
        evidence_digest: parameters[3],
        leaf_hash: parameters[4],
        inclusion_path: parameters[5],
      });
      return [{ affectedRows: 1 }, []];
    }
    if (normalized.startsWith("SELECT * FROM anchor_batches")) {
      if (!batch) return [[], []];
      if (normalized.includes("batch_id = ?") && batch.batch_id !== parameters[0]) {
        return [[], []];
      }
      if (
        normalized.includes("batch_state IN") &&
        !actionableStates.has(batch.batch_state)
      ) {
        return [[], []];
      }
      return [[batch], []];
    }
    if (normalized.startsWith("SELECT * FROM anchor_batch_members")) {
      return [
        members.filter(({ batch_id: batchId }) => batchId === parameters[0]),
        [],
      ];
    }
    if (
      normalized.startsWith("UPDATE anchor_batches") &&
      normalized.includes("batch_state = 'SIGNED'")
    ) {
      assert.equal(batch.batch_id, parameters[8]);
      Object.assign(batch, {
        batch_state: "SIGNED",
        transaction_hash: parameters[0],
        transaction_input: parameters[1],
        anchor_address: parameters[2],
        signed_transaction: parameters[3],
        transaction_nonce: parameters[4],
        max_fee_per_gas: parameters[5],
        max_priority_fee_per_gas: parameters[6],
        gas_limit: parameters[7],
      });
      return [{ affectedRows: 1 }, []];
    }
    if (
      normalized.startsWith("UPDATE anchor_batches") &&
      normalized.includes("batch_state = 'SUBMITTED'")
    ) {
      assert.equal(batch.batch_id, parameters[0]);
      batch.batch_state = "SUBMITTED";
      batch.submitted_at = new Date("2026-08-13T02:01:00.000Z");
      return [{ affectedRows: 1 }, []];
    }
    throw new Error(`Unexpected text-protocol SQL: ${normalized}`);
  };
  const connection = {
    query,
    async beginTransaction() {},
    async commit() {},
    async rollback() {},
    release() {},
  };
  const pool = {
    query,
    async execute() {
      throw new Error("Incorrect arguments to COM_STMT_EXECUTE");
    },
    async getConnection() {
      return connection;
    },
  };
  const store = createMysqlRecordStore(pool);
  const batchId = "123e4567-e89b-42d3-a456-426614174111";
  const recordId = "SR-20260813-ABCDEF0123456789ABCDEF01";
  const created = await store.createAnchorBatch({
    batchId,
    protocol: "SITESEALED_MERKLE_SHA256_V1",
    root: "a".repeat(64),
    leafCount: 1,
    members: [
      {
        recordId,
        leafIndex: 0,
        evidenceDigest: "b".repeat(64),
        leafHash: "c".repeat(64),
        inclusionPath: [],
      },
    ],
  });
  assert.equal(created.batch.state, "PREPARED");
  assert.equal((await store.getActionableAnchorBatch()).state, "PREPARED");

  const signed = await store.saveSignedAnchor(batchId, {
    transactionHash: `0x${"d".repeat(64)}`,
    transactionInput: `0x53534c4401${"a".repeat(64)}`,
    anchorAddress: `0x${"e".repeat(40)}`,
    signedTransaction: "0x02f86c",
    nonce: 0,
    maxFeePerGas: "2000000000",
    maxPriorityFeePerGas: "500000000",
    gasLimit: "30000",
  });
  assert.equal(signed.state, "SIGNED");
  assert.equal(signed.nonce, 0);

  const submitted = await store.markAnchorSubmitted(batchId);
  assert.equal(submitted.state, "SUBMITTED");
  assert.equal(queries.length > 0, true);
  assert.equal(
    queries.every(({ parameters }) => Array.isArray(parameters)),
    true,
  );
});

test("public chain proof persistence in updateAnchorBatch keeps values aligned", async () => {
  const calls = [];
  const batchId = "123e4567-e89b-42d3-a456-426614174222";
  const memberRecordId = "SR-20260813-ABCDEF0123456789ABCDEF02";
  const batch = {
    batch_id: batchId,
    merkle_protocol: "SITESEALED_MERKLE_SHA256_V1",
    merkle_root: "a".repeat(64),
    leaf_count: 1,
    chain_name: "Ethereum mainnet",
    chain_id: 1,
    batch_state: "SUBMITTED",
    transaction_hash: `0x${"b".repeat(64)}`,
    transaction_input: `0x53534c4401${"c".repeat(64)}`,
    anchor_address: `0x${"d".repeat(40)}`,
    block_number: 101,
    block_hash: `0x${"e".repeat(64)}`,
    verification_status: "TRANSACTION_SUBMITTED",
    confirmations: 0,
    submitted_at: new Date("2026-08-13T02:01:00.000Z"),
    confirmed_at: null,
    finalized_at: null,
    created_at: new Date("2026-08-13T02:00:00.000Z"),
  };
  const members = [
    {
      batch_id: batchId,
      record_id: memberRecordId,
      leaf_index: 0,
      leaf_hash: "f".repeat(64),
      inclusion_path: JSON.stringify([]),
    },
  ];
  const query = async (sql, parameters = []) => {
    calls.push({ sql, parameters });
    const normalized = sql.replace(/\s+/g, " ").trim();
    if (normalized.startsWith("SELECT * FROM anchor_batch_members")) {
      return [members, []];
    }
    if (normalized.startsWith("SELECT * FROM anchor_batches WHERE batch_id = ? FOR UPDATE")) {
      return [[batch], []];
    }
    if (normalized.startsWith("UPDATE anchor_batches")) {
      Object.assign(batch, {
        batch_state: parameters[0],
        block_number: parameters[1],
        block_hash: parameters[2],
        confirmations: parameters[3],
        verification_status: parameters[4],
        confirmed_at: parameters[6],
        finalized_at: parameters[7],
      });
      return [{ affectedRows: 1 }, []];
    }
    if (normalized.startsWith("INSERT INTO public_chain_proofs")) {
      return [{ affectedRows: 1 }, []];
    }
    if (
      normalized.startsWith(
        "SELECT * FROM anchor_batches WHERE batch_id = ? ORDER BY created_at ASC LIMIT 1",
      )
    ) {
      return [[batch], []];
    }
    throw new Error(`Unexpected text-protocol SQL: ${normalized}`);
  };
  const connection = {
    query,
    async beginTransaction() {},
    async commit() {},
    async rollback() {},
    release() {},
  };
  const pool = {
    query,
    async execute() {
      throw new Error("updateAnchorBatch must use text protocol.");
    },
    async getConnection() {
      return connection;
    },
  };
  const store = createMysqlRecordStore(pool);

  await store.updateAnchorBatch(batchId, {
    state: "CONFIRMED",
    blockNumber: 202,
    blockHash: `0x${"1".repeat(64)}`,
    confirmations: 12,
    verificationStatus: "TRANSACTION_CONFIRMED",
    anchoredAt: "2026-08-13T02:02:00.000Z",
    confirmedAt: "2026-08-13T02:03:00.000Z",
  });

  const chainProofInsert = calls.find(({ sql }) =>
    sql.includes("INSERT INTO public_chain_proofs"),
  );
  assert.ok(chainProofInsert);
  const valuesClause = chainProofInsert.sql.match(
    /\)\s*VALUES\s*\(([\s\S]*?)\)\s*ON DUPLICATE KEY UPDATE/i,
  );
  assert.ok(valuesClause);
  const placeholderCount = (valuesClause[1].match(/\?/g) ?? []).length;

  assert.equal(placeholderCount, chainProofInsert.parameters.length);
  assert.equal(chainProofInsert.parameters.length, 22);
  assert.equal(chainProofInsert.parameters[2], batch.chain_name);
  assert.equal(chainProofInsert.parameters[3], batch.chain_id);
  assert.equal(chainProofInsert.parameters[0], memberRecordId);
  assert.equal(chainProofInsert.parameters[6], batch.transaction_hash);
  assert.equal(chainProofInsert.parameters[10], batch.merkle_root);
});

test("Ethereum MySQL failures identify the exact recovery operation", async () => {
  const pool = {
    async query() {
      const error = new Error("Incorrect arguments to COM_STMT_EXECUTE");
      error.code = "ER_WRONG_ARGUMENTS";
      throw error;
    },
  };

  await assert.rejects(
    () => createMysqlRecordStore(pool).getActionableAnchorBatch(),
    (error) => {
      assert.equal(error.code, "ER_WRONG_ARGUMENTS");
      assert.match(
        error.message,
        /MySQL actionable anchor batch lookup failed: Incorrect arguments to COM_STMT_EXECUTE/,
      );
      return true;
    },
  );
});

test("INVALID_ON_CHAIN anchor batches remain actionable for safe reinspection", async () => {
  let lookupSql = "";
  const pool = {
    async query(sql) {
      lookupSql = sql.replace(/\s+/g, " ").trim();
      return [[], []];
    },
  };

  const batch = await createMysqlRecordStore(pool).getActionableAnchorBatch();

  assert.equal(batch, null);
  assert.match(lookupSql, /'INVALID_ON_CHAIN'/);
});

test("database rows expose the independently verified RFC 3161 path", () => {
  const record = mapRecordRow({
    record_id: "SR-20260812-ABCDEF0123456789ABCDEF01",
    record_sha256: "a".repeat(64),
    manifest_sha256: "b".repeat(64),
    manifest_encryption: "AES-256-GCM / client-held key",
    record_class: "IMPORTED_FILE",
    proof_level: "DUAL_RAIL_ALPHA_RECEIPT",
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
    created_at: new Date("2026-08-12T19:00:00.000Z"),
    qualified_provider: "Evidency",
    qualified_environment: "SANDBOX",
    qualified_legal_use: 0,
    qualification_status: "TEST_ONLY_NOT_QUALIFIED",
    qualified_hash_algorithm: "SHA256",
    qualified_hashed_message: "f".repeat(64),
    qualified_serial_number: "01",
    certified_at: new Date("2026-08-12T19:01:00.000Z"),
    token_der: Buffer.alloc(64, 7),
    qualified_token_sha256: "1".repeat(64),
    qualified_tsa_policy_id: "1.2.3",
    qualified_provider_status: 0,
    qualified_response_validation:
      "RFC3161_CMS_SIGNATURE_CHAIN_AND_DIGEST_VALID",
    qualified_signature_verification: "VALID",
    qualified_validator_version: "SITESEALED_RFC3161_VALIDATOR_V1",
    qualified_certificate_chain_verification:
      "VALID_TO_PINNED_SANDBOX_ROOT",
    qualified_signing_certificate_verification: "ESSCERTIDV2_MATCH",
    qualified_signing_certificate_hash_algorithm: "SHA384",
    qualified_cms_algorithm_protection: "VALID",
    qualified_revocation_verification: "NOT_CHECKED",
    qualified_cms_digest_algorithm: "SHA512",
    qualified_cms_signature_algorithm: "RSA_PKCS1_SHA512",
    qualified_signer_certificate_sha256: "2".repeat(64),
    qualified_trust_anchor_sha256: "3".repeat(64),
    qualified_certificate_path_length: 3,
  });

  assert.equal(record.qualifiedRail.signatureVerification, "VALID");
  assert.equal(
    record.qualifiedRail.certificateChainVerification,
    "VALID_TO_PINNED_SANDBOX_ROOT",
  );
  assert.equal(record.qualifiedRail.revocationVerification, "NOT_CHECKED");
  assert.equal(record.qualifiedRail.certificatePathLength, 3);
  assert.equal(
    externalProofStatus(record).state,
    "SANDBOX_TIMESTAMP_ISSUED_ANCHOR_PENDING",
  );
});

test("MySQL persistence rejects an unverified timestamp proof before writing", async () => {
  const store = createMysqlRecordStore({
    async getConnection() {
      throw new Error("The database must not be contacted for an unverified proof.");
    },
  });
  await assert.rejects(
    store.saveQualifiedTimestamp("SR-20260812-ABCDEF0123456789ABCDEF01", {
      signatureVerification: "NOT_INDEPENDENTLY_VERIFIED",
    }),
    (error) => error.code === "TIMESTAMP_PROOF_NOT_VERIFIED",
  );
});

test("automatic rail selection uses validated integer LIMIT literals", async () => {
  const queries = [];
  const pool = {
    async query(sql, parameters) {
      queries.push({ sql, parameters });
      return [[], []];
    },
    async execute() {
      throw new Error("Candidate selection must not use prepared LIMIT parameters.");
    },
  };
  const store = createMysqlRecordStore(pool);

  await store.listTimestampCandidates(50);
  await store.listAnchorCandidates(1024);
  await store.listTimestampCandidates("1; DROP TABLE sealed_records");

  assert.equal(queries.length, 3);
  assert.match(queries[0].sql, /LIMIT 50\s*$/);
  assert.match(queries[1].sql, /LIMIT 1024\s*$/);
  assert.match(queries[1].sql, /SITESEALED_RFC3161_VALIDATOR_V1/);
  assert.match(queries[1].sql, /signature_verification = 'VALID'/);
  assert.match(
    queries[1].sql,
    /certificate_chain_verification =\s*'VALID_TO_PINNED_SANDBOX_ROOT'/,
  );
  assert.match(queries[2].sql, /LIMIT 50\s*$/);
  assert.equal(queries.some(({ sql }) => sql.includes("LIMIT ?")), false);
  assert.equal(
    queries.some(({ sql }) => sql.includes("DROP TABLE")),
    false,
  );
  assert.equal(queries.every(({ parameters }) => parameters === undefined), true);
});

test("MySQL receipt creation stores digests, encrypted manifest and private S3 reference", async () => {
  const calls = [];
  const pool = {
    async query(sql, parameters) {
      calls.push({ sql, parameters });
      if (sql.includes("WHERE records.submission_id")) return [[], []];
      throw new Error(`Unexpected SQL: ${sql}`);
    },
    async execute(sql, parameters) {
      calls.push({ sql, parameters });
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
  assert.equal(result.record.proofLevel, "DUAL_RAIL_ALPHA_RECEIPT");
  const insert = calls.find((call) => call.sql.startsWith("INSERT INTO sealed_records"));
  assert.ok(insert);
  assert.equal(insert.parameters.includes(input.recordSha256), true);
  assert.equal(insert.parameters.some((value) => Buffer.isBuffer(value)), true);
  assert.equal(insert.parameters.some((value) => value === "DUAL_RAIL_ALPHA_RECEIPT"), true);
  assert.equal(insert.parameters.includes("1.5-alpha.1"), true);
  assert.equal(insert.parameters.includes(encryptedObject().objectKey), true);
  assert.equal(insert.parameters.includes(storageCipherSha256), true);
  assert.equal(insert.parameters.includes("STORED_ENCRYPTED"), true);
  assert.equal(insert.parameters.some((value) => value === "original bytes"), false);
});
