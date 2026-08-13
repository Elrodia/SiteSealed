import mysql from "mysql2/promise";
import {
  ApiError,
  chainRailFromProof,
  createDevelopmentRecord,
  createEvidenceDigest,
  createProofBundle,
  createReceiptPayload,
  parseEncryptedManifest,
  qualifiedRailFromProof,
  serializeEncryptedManifest,
} from "./records.js";
import { specimenRecord } from "./specimen.js";

const MIGRATION_LOCK = "sitesealed_schema_migrations";
const REQUIRED_CONFIG_KEYS = [
  "MYSQLHOST",
  "MYSQLPORT",
  "MYSQLUSER",
  "MYSQLPASSWORD",
  "MYSQLDATABASE",
];

function boundedSqlLimit(value, { fallback, maximum }) {
  const numeric =
    typeof value === "number" ? value : Number(String(value ?? "").trim());
  if (!Number.isSafeInteger(numeric) || numeric <= 0) return fallback;
  return Math.min(numeric, maximum);
}

function mysqlOperationError(operation, error) {
  const detail = String(error?.message ?? "Unknown MySQL failure.");
  const wrapped = new Error(`MySQL ${operation} failed: ${detail}`, {
    cause: error,
  });
  for (const field of ["code", "errno", "sqlState", "sqlMessage"]) {
    if (error?.[field] !== undefined) wrapped[field] = error[field];
  }
  return wrapped;
}

async function textQuery(client, operation, sql, parameters) {
  try {
    return parameters === undefined
      ? await client.query(sql)
      : await client.query(sql, parameters);
  } catch (error) {
    throw mysqlOperationError(operation, error);
  }
}

const schemaStatements = [
  `CREATE TABLE IF NOT EXISTS sealed_records (
    record_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    submission_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    record_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    manifest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    encrypted_manifest LONGBLOB NULL,
    manifest_encryption VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    specimen_payload JSON NULL,
    record_class VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'LEGACY',
    proof_level VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'DUAL_RAIL',
    receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    client_protocol VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
    storage_provider VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
    storage_object_key VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
    storage_cipher_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    storage_cipher_iv VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
    storage_cipher_bytes BIGINT UNSIGNED NULL,
    storage_plaintext_bytes BIGINT UNSIGNED NULL,
    storage_recovery_token_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    storage_status VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'NOT_STORED',
    record_status VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    is_specimen TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (record_id),
    UNIQUE INDEX idx_sealed_records_submission_id (submission_id),
    INDEX idx_sealed_records_record_sha256 (record_sha256),
    INDEX idx_sealed_records_manifest_sha256 (manifest_sha256),
    INDEX idx_sealed_records_receipt_sha256 (receipt_sha256)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci`,
  `CREATE TABLE IF NOT EXISTS qualified_timestamp_proofs (
    record_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    provider_name VARCHAR(255) NOT NULL,
    token_reference VARCHAR(255) NOT NULL,
    certified_at DATETIME(3) NOT NULL,
    verification_status VARCHAR(255) NOT NULL,
    token_der LONGBLOB NULL,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (record_id),
    CONSTRAINT fk_qualified_proof_record
      FOREIGN KEY (record_id) REFERENCES sealed_records (record_id)
      ON UPDATE RESTRICT ON DELETE RESTRICT
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci`,
  `CREATE TABLE IF NOT EXISTS public_chain_proofs (
    record_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    chain_name VARCHAR(160) NOT NULL,
    block_number BIGINT UNSIGNED NULL,
    transaction_hash VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    anchored_at DATETIME(3) NULL,
    merkle_root VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    inclusion_path JSON NULL,
    batch_size INT UNSIGNED NOT NULL,
    verification_status VARCHAR(255) NOT NULL,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (record_id),
    INDEX idx_public_chain_transaction (transaction_hash),
    CONSTRAINT fk_chain_proof_record
      FOREIGN KEY (record_id) REFERENCES sealed_records (record_id)
      ON UPDATE RESTRICT ON DELETE RESTRICT
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci`,
];

async function ensureColumn(connection, tableName, columnName, definition) {
  const [rows] = await connection.execute(
    `SELECT 1 AS present
       FROM information_schema.columns
      WHERE table_schema = DATABASE()
        AND table_name = ?
        AND column_name = ?
      LIMIT 1`,
    [tableName, columnName],
  );
  if (rows.length === 0) {
    await connection.query(
      `ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`,
    );
  }
}

async function ensureIndex(connection, tableName, indexName, definition) {
  const [rows] = await connection.execute(
    `SELECT 1 AS present
       FROM information_schema.statistics
      WHERE table_schema = DATABASE()
        AND table_name = ?
        AND index_name = ?
      LIMIT 1`,
    [tableName, indexName],
  );
  if (rows.length === 0) {
    await connection.query(`ALTER TABLE ${tableName} ADD ${definition}`);
  }
}

const migrations = [
  {
    id: "001_genesis_evidence_records",
    async up(connection) {
      for (const statement of schemaStatements) {
        await connection.query(statement);
      }
    },
  },
  {
    id: "002_development_sealing_receipts",
    async up(connection) {
      await ensureColumn(
        connection,
        "sealed_records",
        "submission_id",
        "CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER record_id",
      );
      await ensureColumn(
        connection,
        "sealed_records",
        "record_class",
        "VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'LEGACY' AFTER specimen_payload",
      );
      await ensureColumn(
        connection,
        "sealed_records",
        "proof_level",
        "VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'DUAL_RAIL' AFTER record_class",
      );
      await ensureColumn(
        connection,
        "sealed_records",
        "receipt_sha256",
        "CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER proof_level",
      );
      await ensureColumn(
        connection,
        "sealed_records",
        "client_protocol",
        "VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER receipt_sha256",
      );
      await ensureIndex(
        connection,
        "sealed_records",
        "idx_sealed_records_submission_id",
        "UNIQUE INDEX idx_sealed_records_submission_id (submission_id)",
      );
      await ensureIndex(
        connection,
        "sealed_records",
        "idx_sealed_records_receipt_sha256",
        "INDEX idx_sealed_records_receipt_sha256 (receipt_sha256)",
      );
    },
  },
  {
    id: "003_private_encrypted_object_storage",
    async up(connection) {
      await ensureColumn(
        connection,
        "sealed_records",
        "storage_provider",
        "VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER client_protocol",
      );
      await ensureColumn(
        connection,
        "sealed_records",
        "storage_object_key",
        "VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER storage_provider",
      );
      await ensureColumn(
        connection,
        "sealed_records",
        "storage_cipher_sha256",
        "CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER storage_object_key",
      );
      await ensureColumn(
        connection,
        "sealed_records",
        "storage_cipher_iv",
        "VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER storage_cipher_sha256",
      );
      await ensureColumn(
        connection,
        "sealed_records",
        "storage_cipher_bytes",
        "BIGINT UNSIGNED NULL AFTER storage_cipher_iv",
      );
      await ensureColumn(
        connection,
        "sealed_records",
        "storage_plaintext_bytes",
        "BIGINT UNSIGNED NULL AFTER storage_cipher_bytes",
      );
      await ensureColumn(
        connection,
        "sealed_records",
        "storage_recovery_token_sha256",
        "CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER storage_plaintext_bytes",
      );
      await ensureColumn(
        connection,
        "sealed_records",
        "storage_status",
        "VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'NOT_STORED' AFTER storage_recovery_token_sha256",
      );
      await ensureIndex(
        connection,
        "sealed_records",
        "idx_sealed_records_storage_object_key",
        "UNIQUE INDEX idx_sealed_records_storage_object_key (storage_object_key)",
      );
      await ensureIndex(
        connection,
        "sealed_records",
        "idx_sealed_records_storage_cipher_sha256",
        "INDEX idx_sealed_records_storage_cipher_sha256 (storage_cipher_sha256)",
      );
    },
  },
  {
    id: "004_dual_rail_alpha",
    async up(connection) {
      await ensureColumn(
        connection,
        "sealed_records",
        "receipt_version",
        "VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '1.2' AFTER receipt_sha256",
      );

      const qualifiedColumns = [
        ["environment", "VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'PRODUCTION' AFTER provider_name"],
        ["legal_use", "TINYINT(1) NOT NULL DEFAULT 0 AFTER environment"],
        ["qualification_status", "VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'UNDETERMINED' AFTER legal_use"],
        ["hash_algorithm", "VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'SHA256' AFTER qualification_status"],
        ["hashed_message", "CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER hash_algorithm"],
        ["serial_number", "VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER hashed_message"],
        ["token_sha256", "CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER token_der"],
        ["tsa_policy_id", "VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER token_sha256"],
        ["provider_status", "INT NULL AFTER tsa_policy_id"],
        ["response_validation", "VARCHAR(96) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER provider_status"],
        ["signature_verification", "VARCHAR(96) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'NOT_INDEPENDENTLY_VERIFIED' AFTER response_validation"],
      ];
      for (const [name, definition] of qualifiedColumns) {
        await ensureColumn(
          connection,
          "qualified_timestamp_proofs",
          name,
          definition,
        );
      }
      await ensureIndex(
        connection,
        "qualified_timestamp_proofs",
        "idx_qualified_timestamp_hashed_message",
        "INDEX idx_qualified_timestamp_hashed_message (hashed_message)",
      );

      const chainColumns = [
        ["batch_id", "CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER record_id"],
        ["chain_id", "BIGINT UNSIGNED NOT NULL DEFAULT 1 AFTER chain_name"],
        ["transaction_input", "VARCHAR(160) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER transaction_hash"],
        ["anchor_address", "CHAR(42) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER transaction_input"],
        ["block_hash", "CHAR(66) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER block_number"],
        ["leaf_index", "INT UNSIGNED NULL AFTER merkle_root"],
        ["leaf_hash", "CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER leaf_index"],
        ["merkle_protocol", "VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'SITESEALED_MERKLE_SHA256_V1' AFTER leaf_hash"],
        ["confirmations", "INT UNSIGNED NOT NULL DEFAULT 0 AFTER verification_status"],
        ["finality_status", "VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'SUBMITTED' AFTER confirmations"],
        ["submitted_at", "DATETIME(3) NULL AFTER finality_status"],
        ["confirmed_at", "DATETIME(3) NULL AFTER submitted_at"],
        ["finalized_at", "DATETIME(3) NULL AFTER confirmed_at"],
      ];
      for (const [name, definition] of chainColumns) {
        await ensureColumn(connection, "public_chain_proofs", name, definition);
      }

      await connection.query(`CREATE TABLE IF NOT EXISTS anchor_batches (
        batch_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        merkle_protocol VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        merkle_root CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        leaf_count INT UNSIGNED NOT NULL,
        chain_name VARCHAR(64) NOT NULL DEFAULT 'Ethereum mainnet',
        chain_id BIGINT UNSIGNED NOT NULL DEFAULT 1,
        batch_state VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        transaction_hash CHAR(66) CHARACTER SET ascii COLLATE ascii_bin NULL,
        transaction_input VARCHAR(160) CHARACTER SET ascii COLLATE ascii_bin NULL,
        anchor_address CHAR(42) CHARACTER SET ascii COLLATE ascii_bin NULL,
        signed_transaction LONGBLOB NULL,
        transaction_nonce BIGINT UNSIGNED NULL,
        max_fee_per_gas VARCHAR(80) CHARACTER SET ascii COLLATE ascii_bin NULL,
        max_priority_fee_per_gas VARCHAR(80) CHARACTER SET ascii COLLATE ascii_bin NULL,
        gas_limit VARCHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL,
        block_number BIGINT UNSIGNED NULL,
        block_hash CHAR(66) CHARACTER SET ascii COLLATE ascii_bin NULL,
        confirmations INT UNSIGNED NOT NULL DEFAULT 0,
        verification_status VARCHAR(96) CHARACTER SET ascii COLLATE ascii_bin NULL,
        error_code VARCHAR(96) CHARACTER SET ascii COLLATE ascii_bin NULL,
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        signed_at DATETIME(3) NULL,
        submitted_at DATETIME(3) NULL,
        confirmed_at DATETIME(3) NULL,
        finalized_at DATETIME(3) NULL,
        updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (batch_id),
        UNIQUE INDEX idx_anchor_batches_root (merkle_root),
        UNIQUE INDEX idx_anchor_batches_transaction (transaction_hash),
        INDEX idx_anchor_batches_state (batch_state, created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci`);

      await connection.query(`CREATE TABLE IF NOT EXISTS anchor_batch_members (
        batch_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        record_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        leaf_index INT UNSIGNED NOT NULL,
        evidence_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        leaf_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        inclusion_path JSON NOT NULL,
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        PRIMARY KEY (batch_id, record_id),
        UNIQUE INDEX idx_anchor_member_record (record_id),
        CONSTRAINT fk_anchor_member_batch
          FOREIGN KEY (batch_id) REFERENCES anchor_batches (batch_id)
          ON UPDATE RESTRICT ON DELETE RESTRICT,
        CONSTRAINT fk_anchor_member_record
          FOREIGN KEY (record_id) REFERENCES sealed_records (record_id)
          ON UPDATE RESTRICT ON DELETE RESTRICT
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci`);
    },
  },
  {
    id: "005_rfc3161_independent_verification",
    async up(connection) {
      const verificationColumns = [
        ["validator_version", "VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER signature_verification"],
        ["certificate_chain_verification", "VARCHAR(96) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER validator_version"],
        ["signing_certificate_verification", "VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER certificate_chain_verification"],
        ["signing_certificate_hash_algorithm", "VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER signing_certificate_verification"],
        ["cms_algorithm_protection", "VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER signing_certificate_hash_algorithm"],
        ["revocation_verification", "VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER cms_algorithm_protection"],
        ["cms_digest_algorithm", "VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER revocation_verification"],
        ["cms_signature_algorithm", "VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER cms_digest_algorithm"],
        ["signer_certificate_sha256", "CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER cms_signature_algorithm"],
        ["trust_anchor_sha256", "CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER signer_certificate_sha256"],
        ["certificate_path_length", "TINYINT UNSIGNED NULL AFTER trust_anchor_sha256"],
      ];
      for (const [name, definition] of verificationColumns) {
        await ensureColumn(
          connection,
          "qualified_timestamp_proofs",
          name,
          definition,
        );
      }
    },
  },
];

function databaseMode(environment) {
  const mode = String(environment.DATABASE_MODE ?? "optional")
    .trim()
    .toLowerCase();
  if (mode !== "optional" && mode !== "required") {
    throw new Error('DATABASE_MODE must be either "optional" or "required".');
  }
  return mode;
}

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function parseMysqlUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("MYSQL_URL must be a valid MySQL connection URL.");
  }

  if (url.protocol !== "mysql:") {
    throw new Error("MYSQL_URL must use the mysql:// protocol.");
  }

  const database = decodeURIComponent(url.pathname.replace(/^\//, ""));
  if (!url.hostname || !url.username || !database) {
    throw new Error("MYSQL_URL must include a host, user and database name.");
  }

  return {
    host: url.hostname,
    port: positiveInteger(url.port, 3306),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database,
  };
}

export function resolveDatabaseConfig(environment = process.env) {
  const mode = databaseMode(environment);
  const rawUrl = String(environment.MYSQL_URL ?? "").trim();

  if (rawUrl) {
    return {
      ...parseMysqlUrl(rawUrl),
      connectionLimit: positiveInteger(environment.MYSQL_CONNECTION_LIMIT, 5),
    };
  }

  const presentKeys = REQUIRED_CONFIG_KEYS.filter((key) =>
    String(environment[key] ?? "").trim(),
  );
  if (presentKeys.length === 0) {
    if (mode === "required") {
      throw new Error(
        "MySQL is required but MYSQL_URL is not configured for this service.",
      );
    }
    return null;
  }

  const missingKeys = REQUIRED_CONFIG_KEYS.filter(
    (key) => !String(environment[key] ?? "").trim(),
  );
  if (missingKeys.length > 0) {
    throw new Error(
      `Incomplete MySQL configuration. Missing: ${missingKeys.join(", ")}.`,
    );
  }

  return {
    host: environment.MYSQLHOST,
    port: positiveInteger(environment.MYSQLPORT, 3306),
    user: environment.MYSQLUSER,
    password: environment.MYSQLPASSWORD,
    database: environment.MYSQLDATABASE,
    connectionLimit: positiveInteger(environment.MYSQL_CONNECTION_LIMIT, 5),
  };
}

export function createDatabasePool(config) {
  return mysql.createPool({
    host: config.host,
    port: config.port,
    user: config.user,
    password: config.password,
    database: config.database,
    waitForConnections: true,
    connectionLimit: config.connectionLimit,
    maxIdle: config.connectionLimit,
    idleTimeout: 60_000,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0,
    charset: "utf8mb4",
    timezone: "Z",
  });
}

async function seedSpecimen(connection) {
  const record = specimenRecord;
  const specimenPayload = JSON.stringify({
    classification: record.classification,
    project: record.project,
    description: record.description,
    file: record.file,
    captureMode: record.captureMode,
    capturedAt: record.capturedAt,
    position: record.position,
  });

  await connection.beginTransaction();
  try {
    await connection.execute(
      `INSERT IGNORE INTO sealed_records (
        record_id, submission_id, record_sha256, manifest_sha256,
        encrypted_manifest, manifest_encryption, specimen_payload,
        record_class, proof_level, receipt_sha256, client_protocol,
        record_status, is_specimen
      ) VALUES (?, NULL, ?, ?, NULL, ?, ?, ?, ?, NULL, ?, ?, ?)`,
      [
        record.recordId,
        record.sha256,
        record.manifestSha256,
        "PUBLIC_SPECIMEN",
        specimenPayload,
        record.recordClass,
        record.proofLevel,
        "SPECIMEN",
        "SEALED_SPECIMEN",
        1,
      ],
    );

    await connection.execute(
      `UPDATE sealed_records
          SET record_class = ?, proof_level = ?, client_protocol = ?
        WHERE record_id = ? AND is_specimen = 1`,
      [record.recordClass, record.proofLevel, "SPECIMEN", record.recordId],
    );

    await connection.execute(
      `INSERT IGNORE INTO qualified_timestamp_proofs (
        record_id, provider_name, token_reference, certified_at,
        verification_status, token_der
      ) VALUES (?, ?, ?, ?, ?, NULL)`,
      [
        record.recordId,
        record.qualifiedRail.provider,
        record.qualifiedRail.token,
        new Date(record.qualifiedAt),
        record.qualifiedRail.status,
      ],
    );

    await connection.execute(
      `INSERT IGNORE INTO public_chain_proofs (
        record_id, chain_name, block_number, transaction_hash, anchored_at,
        merkle_root, inclusion_path, batch_size, verification_status
      ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
      [
        record.recordId,
        record.chainRail.chain,
        21_904_553,
        record.chainRail.anchor,
        new Date("2026-08-10T12:00:11.000Z"),
        record.chainRail.merkleRoot,
        record.chainRail.batchSize,
        record.chainRail.status,
      ],
    );

    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  }
}

export async function runMigrations(pool) {
  const connection = await pool.getConnection();
  let lockAcquired = false;
  const applied = [];

  try {
    const [lockRows] = await connection.execute(
      "SELECT GET_LOCK(?, 30) AS acquired",
      [MIGRATION_LOCK],
    );
    lockAcquired = Number(lockRows[0]?.acquired) === 1;
    if (!lockAcquired) {
      throw new Error("Could not acquire the SiteSealed migration lock.");
    }

    await connection.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      migration_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
      applied_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      PRIMARY KEY (migration_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci`);

    for (const migration of migrations) {
      const [rows] = await connection.execute(
        "SELECT migration_id FROM schema_migrations WHERE migration_id = ? LIMIT 1",
        [migration.id],
      );
      if (rows.length > 0) continue;

      await migration.up(connection);
      await connection.execute(
        "INSERT INTO schema_migrations (migration_id) VALUES (?)",
        [migration.id],
      );
      applied.push(migration.id);
    }

    await seedSpecimen(connection);
    return { applied };
  } finally {
    if (lockAcquired) {
      await connection
        .execute("SELECT RELEASE_LOCK(?)", [MIGRATION_LOCK])
        .catch(() => {});
    }
    connection.release();
  }
}

function isoTimestamp(value) {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? null : parsed.toISOString();
}

function parseJsonColumn(value) {
  if (!value) return {};
  if (typeof value === "object") return value;
  try {
    return JSON.parse(value);
  } catch {
    return {};
  }
}

function encryptedObjectFromRow(row) {
  if (
    row.storage_status !== "STORED_ENCRYPTED" ||
    !row.storage_object_key ||
    !row.storage_cipher_sha256 ||
    !row.storage_cipher_iv ||
    !row.storage_recovery_token_sha256
  ) {
    return null;
  }
  return {
    version: 1,
    storageClass: "PRIVATE_CLIENT_ENCRYPTED_ORIGINAL",
    objectKey: row.storage_object_key,
    algorithm: "AES-256-GCM",
    iv: row.storage_cipher_iv,
    ciphertextSha256: row.storage_cipher_sha256,
    ciphertextBytes: Number(row.storage_cipher_bytes),
    plaintextBytes: Number(row.storage_plaintext_bytes),
    recoveryTokenSha256: row.storage_recovery_token_sha256,
  };
}

function assertIdempotentInputMatches(row, input) {
  const storedObject = encryptedObjectFromRow(row);
  const matches =
    row.record_sha256 === input.recordSha256 &&
    row.manifest_sha256 === input.manifestSha256 &&
    storedObject?.ciphertextSha256 === input.encryptedObject.ciphertextSha256 &&
    storedObject?.objectKey === input.encryptedObject.objectKey &&
    storedObject?.recoveryTokenSha256 ===
      input.encryptedObject.recoveryTokenSha256;
  if (!matches) {
    throw new ApiError(
      409,
      "SUBMISSION_ID_CONFLICT",
      "This submission ID is already bound to a different encrypted record.",
    );
  }
}

export function mapRecordRow(row) {
  const receivedAt = isoTimestamp(row.created_at);
  if (!Boolean(row.is_specimen)) {
    const encryptedObject = encryptedObjectFromRow(row);
    const record = createDevelopmentRecord(
      {
        recordClass: row.record_class,
        recordSha256: row.record_sha256,
        manifestSha256: row.manifest_sha256,
        encryptedObject,
      },
      {
        recordId: row.record_id,
        receivedAt: new Date(receivedAt),
        storageProvider: row.storage_provider,
        receiptVersion: row.receipt_version ?? "1.2",
        proofLevel: row.proof_level,
      },
    );
    const qualifiedRail = row.qualified_provider
      ? qualifiedRailFromProof({
          provider: row.qualified_provider,
          environment: row.qualified_environment,
          legalUse: Boolean(row.qualified_legal_use),
          qualificationStatus: row.qualification_status,
          hashAlgorithm: row.qualified_hash_algorithm,
          hashedMessage: row.qualified_hashed_message,
          serialNumber: row.qualified_serial_number ?? row.token_reference,
          certifiedAt: isoTimestamp(row.certified_at),
          tokenBase64: row.token_der
            ? Buffer.from(row.token_der).toString("base64")
            : null,
          tokenSha256: row.qualified_token_sha256,
          tsaPolicyId: row.qualified_tsa_policy_id,
          providerStatus: row.qualified_provider_status,
          responseValidation: row.qualified_response_validation,
          signatureVerification: row.qualified_signature_verification,
          validatorVersion: row.qualified_validator_version,
          certificateChainVerification:
            row.qualified_certificate_chain_verification,
          signingCertificateVerification:
            row.qualified_signing_certificate_verification,
          signingCertificateHashAlgorithm:
            row.qualified_signing_certificate_hash_algorithm,
          cmsAlgorithmProtection:
            row.qualified_cms_algorithm_protection,
          revocationVerification:
            row.qualified_revocation_verification,
          cmsDigestAlgorithm: row.qualified_cms_digest_algorithm,
          cmsSignatureAlgorithm: row.qualified_cms_signature_algorithm,
          signerCertificateSha256:
            row.qualified_signer_certificate_sha256,
          trustAnchorSha256: row.qualified_trust_anchor_sha256,
          certificatePathLength: row.qualified_certificate_path_length,
        })
      : null;
    const chainRail = row.transaction_hash
      ? chainRailFromProof({
          state: row.chain_finality_status ?? "SUBMITTED",
          chain: row.chain_name,
          chainId: row.chain_id,
          batchId: row.chain_batch_id,
          transactionHash: row.transaction_hash,
          transactionInput: row.transaction_input,
          anchorAddress: row.anchor_address,
          blockNumber: row.block_number,
          blockHash: row.block_hash,
          merkleRoot: row.merkle_root,
          leafIndex: row.leaf_index,
          leafHash: row.leaf_hash,
          merkleProtocol: row.merkle_protocol,
          inclusionPath: parseJsonColumn(row.inclusion_path),
          batchSize: row.batch_size,
          confirmations: row.confirmations,
          anchoredAt: isoTimestamp(row.anchored_at),
          finalizedAt: isoTimestamp(row.finalized_at),
          verificationStatus: row.chain_status,
        })
      : null;
    return {
      ...record,
      manifestEncryption:
        row.manifest_encryption ?? "AES-256-GCM / client-held key",
      receiptSha256: row.receipt_sha256 ?? record.receiptSha256,
      ...(qualifiedRail
        ? { qualifiedAt: qualifiedRail.certifiedAt, qualifiedRail }
        : {}),
      ...(chainRail ? { chainRail } : {}),
    };
  }

  const payload = parseJsonColumn(row.specimen_payload);
  return {
    recordId: row.record_id,
    specimen: true,
    recordClass: row.record_class ?? "LIVE_CAPTURE_SPECIMEN",
    proofLevel: row.proof_level ?? "SIMULATED_DUAL_RAIL",
    classification: payload.classification ?? specimenRecord.classification,
    project: payload.project ?? specimenRecord.project,
    description: payload.description ?? specimenRecord.description,
    file: payload.file ?? specimenRecord.file,
    captureMode: payload.captureMode ?? specimenRecord.captureMode,
    capturedAt: isoTimestamp(payload.capturedAt),
    receivedAt: isoTimestamp(row.certified_at) ?? receivedAt,
    qualifiedAt: isoTimestamp(row.certified_at),
    position: payload.position ?? specimenRecord.position,
    sha256: row.record_sha256,
    manifestSha256: row.manifest_sha256,
    manifestEncryption: row.manifest_encryption,
    receipt: null,
    receiptSha256: null,
    qualifiedRail: {
      state: "SIMULATED",
      provider: row.qualified_provider,
      token: row.token_reference,
      status: row.qualified_status,
    },
    chainRail: {
      state: "SIMULATED",
      chain: row.chain_name,
      block:
        row.block_number === null || row.block_number === undefined
          ? null
          : Number(row.block_number).toLocaleString("en-US"),
      anchor: row.transaction_hash,
      merkleRoot: row.merkle_root,
      batchSize:
        row.batch_size === null || row.batch_size === undefined
          ? null
          : Number(row.batch_size),
      status: row.chain_status,
    },
  };
}

const recordSelect = `SELECT
  records.record_id,
  records.submission_id,
  records.record_sha256,
  records.manifest_sha256,
  records.encrypted_manifest,
  records.manifest_encryption,
  records.specimen_payload,
  records.record_class,
  records.proof_level,
  records.receipt_sha256,
  records.receipt_version,
  records.client_protocol,
  records.storage_provider,
  records.storage_object_key,
  records.storage_cipher_sha256,
  records.storage_cipher_iv,
  records.storage_cipher_bytes,
  records.storage_plaintext_bytes,
  records.storage_recovery_token_sha256,
  records.storage_status,
  records.record_status,
  records.is_specimen,
  records.created_at,
  qualified.provider_name AS qualified_provider,
  qualified.environment AS qualified_environment,
  qualified.legal_use AS qualified_legal_use,
  qualified.qualification_status,
  qualified.hash_algorithm AS qualified_hash_algorithm,
  qualified.hashed_message AS qualified_hashed_message,
  qualified.serial_number AS qualified_serial_number,
  qualified.token_reference,
  qualified.certified_at,
  qualified.token_der,
  qualified.token_sha256 AS qualified_token_sha256,
  qualified.tsa_policy_id AS qualified_tsa_policy_id,
  qualified.provider_status AS qualified_provider_status,
  qualified.response_validation AS qualified_response_validation,
  qualified.signature_verification AS qualified_signature_verification,
  qualified.validator_version AS qualified_validator_version,
  qualified.certificate_chain_verification AS qualified_certificate_chain_verification,
  qualified.signing_certificate_verification AS qualified_signing_certificate_verification,
  qualified.signing_certificate_hash_algorithm AS qualified_signing_certificate_hash_algorithm,
  qualified.cms_algorithm_protection AS qualified_cms_algorithm_protection,
  qualified.revocation_verification AS qualified_revocation_verification,
  qualified.cms_digest_algorithm AS qualified_cms_digest_algorithm,
  qualified.cms_signature_algorithm AS qualified_cms_signature_algorithm,
  qualified.signer_certificate_sha256 AS qualified_signer_certificate_sha256,
  qualified.trust_anchor_sha256 AS qualified_trust_anchor_sha256,
  qualified.certificate_path_length AS qualified_certificate_path_length,
  qualified.verification_status AS qualified_status,
  chain_proof.batch_id AS chain_batch_id,
  chain_proof.chain_name,
  chain_proof.chain_id,
  chain_proof.block_number,
  chain_proof.block_hash,
  chain_proof.transaction_hash,
  chain_proof.transaction_input,
  chain_proof.anchor_address,
  chain_proof.merkle_root,
  chain_proof.leaf_index,
  chain_proof.leaf_hash,
  chain_proof.merkle_protocol,
  chain_proof.inclusion_path,
  chain_proof.batch_size,
  chain_proof.confirmations,
  chain_proof.finality_status AS chain_finality_status,
  chain_proof.anchored_at,
  chain_proof.finalized_at,
  chain_proof.verification_status AS chain_status
FROM sealed_records AS records
LEFT JOIN qualified_timestamp_proofs AS qualified
  ON qualified.record_id = records.record_id
LEFT JOIN public_chain_proofs AS chain_proof
  ON chain_proof.record_id = records.record_id`;

function mapAnchorBatch(batchRow, memberRows = []) {
  if (!batchRow) return null;
  return {
    batchId: batchRow.batch_id,
    protocol: batchRow.merkle_protocol,
    root: batchRow.merkle_root,
    leafCount: Number(batchRow.leaf_count),
    chain: batchRow.chain_name,
    chainId: Number(batchRow.chain_id),
    state: batchRow.batch_state,
    transactionHash: batchRow.transaction_hash,
    transactionInput: batchRow.transaction_input,
    anchorAddress: batchRow.anchor_address,
    signedTransaction: batchRow.signed_transaction
      ? Buffer.from(batchRow.signed_transaction).toString("utf8")
      : null,
    nonce:
      batchRow.transaction_nonce === null ||
      batchRow.transaction_nonce === undefined
        ? null
        : Number(batchRow.transaction_nonce),
    maxFeePerGas: batchRow.max_fee_per_gas,
    maxPriorityFeePerGas: batchRow.max_priority_fee_per_gas,
    gasLimit: batchRow.gas_limit,
    blockNumber:
      batchRow.block_number === null || batchRow.block_number === undefined
        ? null
        : Number(batchRow.block_number),
    blockHash: batchRow.block_hash,
    confirmations: Number(batchRow.confirmations ?? 0),
    verificationStatus: batchRow.verification_status,
    errorCode: batchRow.error_code,
    createdAt: isoTimestamp(batchRow.created_at),
    signedAt: isoTimestamp(batchRow.signed_at),
    submittedAt: isoTimestamp(batchRow.submitted_at),
    confirmedAt: isoTimestamp(batchRow.confirmed_at),
    finalizedAt: isoTimestamp(batchRow.finalized_at),
    members: memberRows.map((row) => ({
      recordId: row.record_id,
      leafIndex: Number(row.leaf_index),
      evidenceDigest: row.evidence_digest,
      leafHash: row.leaf_hash,
      inclusionPath: parseJsonColumn(row.inclusion_path),
    })),
  };
}

async function findAnchorBatch(pool, batchId = null) {
  const parameters = [];
  let where =
    "WHERE batch_state IN ('PREPARED', 'SIGNED', 'SUBMITTED', 'CONFIRMED', 'INVALID_ON_CHAIN')";
  if (batchId) {
    where = "WHERE batch_id = ?";
    parameters.push(batchId);
  }
  const [batches] = await textQuery(
    pool,
    batchId ? "anchor batch lookup by id" : "actionable anchor batch lookup",
    `SELECT * FROM anchor_batches ${where} ORDER BY created_at ASC LIMIT 1`,
    parameters,
  );
  const batch = batches[0];
  if (!batch) return null;
  const [members] = await textQuery(
    pool,
    "anchor batch member lookup",
    `SELECT * FROM anchor_batch_members
      WHERE batch_id = ? ORDER BY leaf_index ASC`,
    [batch.batch_id],
  );
  return mapAnchorBatch(batch, members);
}

export function createMysqlRecordStore(pool) {
  async function findRow(column, value) {
    const allowedColumns = new Set(["record_id", "submission_id"]);
    if (!allowedColumns.has(column)) throw new Error("Unsupported lookup column.");
    const [rows] = await textQuery(
      pool,
      "record lookup",
      `${recordSelect}
       WHERE records.${column} = ?
         AND records.record_status IN ('DEVELOPMENT_RECEIPT', 'SEALED', 'SEALED_SPECIMEN')
       LIMIT 1`,
      [value],
    );
    return rows[0] ?? null;
  }

  return {
    mode: "mysql",
    persistent: true,

    async create(input) {
      const existingRow = await findRow("submission_id", input.submissionId);
      if (existingRow) {
        assertIdempotentInputMatches(existingRow, input);
        return { record: mapRecordRow(existingRow), created: false };
      }

      for (let attempt = 0; attempt < 3; attempt += 1) {
        const record = createDevelopmentRecord(input, {
          storageProvider: input.storageProvider ?? "S3",
        });
        try {
          await pool.execute(
            `INSERT INTO sealed_records (
              record_id, submission_id, record_sha256, manifest_sha256,
              encrypted_manifest, manifest_encryption, specimen_payload,
              record_class, proof_level, receipt_sha256, receipt_version,
              client_protocol,
              storage_provider, storage_object_key, storage_cipher_sha256,
              storage_cipher_iv, storage_cipher_bytes, storage_plaintext_bytes,
              storage_recovery_token_sha256, storage_status,
              record_status, is_specimen, created_at, updated_at
            ) VALUES (
              ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?, ?, ?, ?,
              ?, 0, ?, ?
            )`,
            [
              record.recordId,
              input.submissionId,
              record.sha256,
              record.manifestSha256,
              serializeEncryptedManifest(input.encryptedManifest),
              record.manifestEncryption,
              record.recordClass,
              record.proofLevel,
              record.receiptSha256,
              "1.4-alpha.1",
              input.protocolVersion,
              input.storageProvider ?? "S3",
              input.encryptedObject.objectKey,
              input.encryptedObject.ciphertextSha256,
              input.encryptedObject.iv,
              input.encryptedObject.ciphertextBytes,
              input.encryptedObject.plaintextBytes,
              input.encryptedObject.recoveryTokenSha256,
              "STORED_ENCRYPTED",
              "DEVELOPMENT_RECEIPT",
              new Date(record.receivedAt),
              new Date(record.receivedAt),
            ],
          );
          return { record, created: true };
        } catch (error) {
          if (error?.code !== "ER_DUP_ENTRY") throw error;
          const duplicate = await findRow("submission_id", input.submissionId);
          if (duplicate) {
            assertIdempotentInputMatches(duplicate, input);
            return { record: mapRecordRow(duplicate), created: false };
          }
          if (attempt === 2) throw error;
        }
      }
      throw new Error("Unable to allocate a unique SiteSealed record ID.");
    },

    async listTimestampCandidates(limit = 50) {
      const candidateLimit = boundedSqlLimit(limit, {
        fallback: 50,
        maximum: 1_000,
      });
      const [ids] = await textQuery(
        pool,
        "automatic Evidency candidate selection",
        `SELECT records.record_id
           FROM sealed_records AS records
           LEFT JOIN qualified_timestamp_proofs AS qualified
             ON qualified.record_id = records.record_id
          WHERE records.is_specimen = 0
            AND records.record_status IN ('DEVELOPMENT_RECEIPT', 'SEALED')
            AND qualified.record_id IS NULL
          ORDER BY records.created_at ASC, records.record_id ASC
          LIMIT ${candidateLimit}`,
      );
      const records = await Promise.all(
        ids.map(async ({ record_id: recordId }) => {
          const row = await findRow("record_id", recordId);
          return row ? mapRecordRow(row) : null;
        }),
      );
      return records.filter(Boolean);
    },

    async saveQualifiedTimestamp(recordId, proof) {
      if (
        proof?.validatorVersion !== "SITESEALED_RFC3161_VALIDATOR_V1" ||
        proof?.signatureVerification !== "VALID" ||
        proof?.certificateChainVerification !==
          "VALID_TO_PINNED_SANDBOX_ROOT"
      ) {
        throw new ApiError(
          409,
          "TIMESTAMP_PROOF_NOT_VERIFIED",
          "The timestamp proof did not pass independent RFC 3161 signature and certificate-chain verification.",
        );
      }
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();
        const [records] = await connection.execute(
          `SELECT record_id, record_sha256, manifest_sha256
             FROM sealed_records
            WHERE record_id = ? AND is_specimen = 0
            FOR UPDATE`,
          [recordId],
        );
        if (records.length === 0) {
          throw new ApiError(404, "RECORD_NOT_FOUND", "Record not found.");
        }
        const evidenceDigest = createEvidenceDigest({
          recordSha256: records[0].record_sha256,
          manifestSha256: records[0].manifest_sha256,
        });
        if (proof.hashedMessage !== evidenceDigest) {
          throw new ApiError(
            409,
            "TIMESTAMP_PROOF_CONFLICT",
            "The timestamp token is not bound to this record's evidence digest.",
          );
        }
        const [existing] = await connection.execute(
          `SELECT hashed_message, token_sha256
             FROM qualified_timestamp_proofs WHERE record_id = ?`,
          [recordId],
        );
        if (existing.length > 0) {
          if (existing[0].hashed_message !== evidenceDigest) {
            throw new ApiError(
              409,
              "TIMESTAMP_PROOF_CONFLICT",
              "This record already carries a timestamp for another digest.",
            );
          }
          await connection.commit();
          const row = await findRow("record_id", recordId);
          return { created: false, record: mapRecordRow(row) };
        }
        await connection.execute(
          `INSERT INTO qualified_timestamp_proofs (
            record_id, provider_name, environment, legal_use,
            qualification_status, hash_algorithm, hashed_message,
            serial_number, token_reference, certified_at,
            verification_status, token_der, token_sha256, tsa_policy_id,
            provider_status, response_validation, signature_verification,
            validator_version, certificate_chain_verification,
            signing_certificate_verification,
            signing_certificate_hash_algorithm, cms_algorithm_protection,
            revocation_verification, cms_digest_algorithm,
            cms_signature_algorithm, signer_certificate_sha256,
            trust_anchor_sha256, certificate_path_length
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            recordId,
            proof.provider,
            proof.environment,
            proof.legalUse ? 1 : 0,
            proof.qualificationStatus,
            proof.hashAlgorithm,
            proof.hashedMessage,
            proof.serialNumber,
            proof.serialNumber,
            new Date(proof.certifiedAt),
            "SANDBOX_TOKEN_ISSUED_CRYPTOGRAPHICALLY_VERIFIED_TEST_ONLY",
            Buffer.from(proof.tokenBase64, "base64"),
            proof.tokenSha256,
            proof.tsaPolicyId,
            proof.providerStatus,
            proof.responseValidation,
            proof.signatureVerification,
            proof.validatorVersion,
            proof.certificateChainVerification,
            proof.signingCertificateVerification,
            proof.signingCertificateHashAlgorithm,
            proof.cmsAlgorithmProtection,
            proof.revocationVerification,
            proof.cmsDigestAlgorithm,
            proof.cmsSignatureAlgorithm,
            proof.signerCertificateSha256,
            proof.trustAnchorSha256,
            proof.certificatePathLength,
          ],
        );
        await connection.commit();
        const row = await findRow("record_id", recordId);
        return { created: true, record: mapRecordRow(row) };
      } catch (error) {
        await connection.rollback().catch(() => {});
        throw error;
      } finally {
        connection.release();
      }
    },

    async listAnchorCandidates(limit = 1024) {
      const candidateLimit = boundedSqlLimit(limit, {
        fallback: 1_024,
        maximum: 10_000,
      });
      const [ids] = await textQuery(
        pool,
        "automatic Ethereum candidate selection",
        `SELECT records.record_id
           FROM sealed_records AS records
           JOIN qualified_timestamp_proofs AS qualified
             ON qualified.record_id = records.record_id
           LEFT JOIN anchor_batch_members AS member
             ON member.record_id = records.record_id
          WHERE records.is_specimen = 0
            AND qualified.environment = 'SANDBOX'
            AND qualified.hashed_message IS NOT NULL
            AND qualified.verification_status =
              'SANDBOX_TOKEN_ISSUED_CRYPTOGRAPHICALLY_VERIFIED_TEST_ONLY'
            AND qualified.response_validation =
              'RFC3161_CMS_SIGNATURE_CHAIN_AND_DIGEST_VALID'
            AND qualified.validator_version =
              'SITESEALED_RFC3161_VALIDATOR_V1'
            AND qualified.signature_verification = 'VALID'
            AND qualified.certificate_chain_verification =
              'VALID_TO_PINNED_SANDBOX_ROOT'
            AND member.record_id IS NULL
          ORDER BY records.created_at ASC, records.record_id ASC
          LIMIT ${candidateLimit}`,
      );
      const records = await Promise.all(
        ids.map(async ({ record_id: recordId }) => {
          const row = await findRow("record_id", recordId);
          return row ? mapRecordRow(row) : null;
        }),
      );
      return records.filter(Boolean);
    },

    async createAnchorBatch(batch) {
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();
        await textQuery(
          connection,
          "anchor batch creation",
          `INSERT INTO anchor_batches (
            batch_id, merkle_protocol, merkle_root, leaf_count,
            chain_name, chain_id, batch_state
          ) VALUES (?, ?, ?, ?, 'Ethereum mainnet', 1, 'PREPARED')`,
          [batch.batchId, batch.protocol, batch.root, batch.leafCount],
        );
        for (const member of batch.members) {
          await textQuery(
            connection,
            "anchor batch member creation",
            `INSERT INTO anchor_batch_members (
              batch_id, record_id, leaf_index, evidence_digest,
              leaf_hash, inclusion_path
            ) VALUES (?, ?, ?, ?, ?, ?)`,
            [
              batch.batchId,
              member.recordId,
              member.leafIndex,
              member.evidenceDigest,
              member.leafHash,
              JSON.stringify(member.inclusionPath),
            ],
          );
        }
        await connection.commit();
        return { created: true, batch: await findAnchorBatch(pool, batch.batchId) };
      } catch (error) {
        await connection.rollback().catch(() => {});
        if (error?.code === "ER_DUP_ENTRY") {
          const existing = await findAnchorBatch(pool, batch.batchId);
          if (existing && existing.root === batch.root) {
            return { created: false, batch: existing };
          }
          throw new ApiError(
            409,
            "ANCHOR_MEMBER_CONFLICT",
            "A record is already assigned to another anchor batch.",
          );
        }
        throw error;
      } finally {
        connection.release();
      }
    },

    async getActionableAnchorBatch() {
      return findAnchorBatch(pool);
    },

    async saveSignedAnchor(batchId, signed) {
      const [result] = await textQuery(
        pool,
        "signed anchor persistence",
        `UPDATE anchor_batches
            SET batch_state = 'SIGNED', transaction_hash = ?,
                transaction_input = ?, anchor_address = ?,
                signed_transaction = ?, transaction_nonce = ?,
                max_fee_per_gas = ?, max_priority_fee_per_gas = ?,
                gas_limit = ?, signed_at = CURRENT_TIMESTAMP(3),
                error_code = NULL
          WHERE batch_id = ? AND batch_state = 'PREPARED'`,
        [
          signed.transactionHash,
          signed.transactionInput,
          signed.anchorAddress,
          Buffer.from(signed.signedTransaction, "utf8"),
          signed.nonce,
          signed.maxFeePerGas,
          signed.maxPriorityFeePerGas,
          signed.gasLimit,
          batchId,
        ],
      );
      if (result.affectedRows !== 1) {
        const existing = await findAnchorBatch(pool, batchId);
        if (!existing) throw new ApiError(404, "ANCHOR_BATCH_NOT_FOUND", "Anchor batch not found.");
        return existing;
      }
      return findAnchorBatch(pool, batchId);
    },

    async markAnchorSubmitted(batchId) {
      await textQuery(
        pool,
        "submitted anchor persistence",
        `UPDATE anchor_batches
            SET batch_state = 'SUBMITTED',
                submitted_at = COALESCE(submitted_at, CURRENT_TIMESTAMP(3)),
                error_code = NULL
          WHERE batch_id = ? AND batch_state IN ('SIGNED', 'SUBMITTED')`,
        [batchId],
      );
      return findAnchorBatch(pool, batchId);
    },

    async updateAnchorBatch(batchId, update) {
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();
        const [members] = await textQuery(
          connection,
          "anchor finality member lookup",
          `SELECT * FROM anchor_batch_members
            WHERE batch_id = ? ORDER BY leaf_index ASC`,
          [batchId],
        );
        const [batches] = await textQuery(
          connection,
          "anchor finality batch lock",
          `SELECT * FROM anchor_batches WHERE batch_id = ? FOR UPDATE`,
          [batchId],
        );
        const batch = batches[0];
        if (!batch) throw new ApiError(404, "ANCHOR_BATCH_NOT_FOUND", "Anchor batch not found.");
        const state = String(update.state ?? batch.batch_state).toUpperCase();
        const confirmedAt =
          state === "CONFIRMED" || state === "FINALIZED"
            ? update.confirmedAt ?? new Date().toISOString()
            : batch.confirmed_at;
        const finalizedAt =
          state === "FINALIZED"
            ? update.finalizedAt ?? new Date().toISOString()
            : batch.finalized_at;
        await textQuery(
          connection,
          "anchor state persistence",
          `UPDATE anchor_batches
              SET batch_state = ?, block_number = ?, block_hash = ?,
                  confirmations = ?, verification_status = ?, error_code = ?,
                  confirmed_at = ?, finalized_at = ?
            WHERE batch_id = ?`,
          [
            state,
            update.blockNumber ?? batch.block_number,
            update.blockHash ?? batch.block_hash,
            update.confirmations ?? batch.confirmations ?? 0,
            update.verificationStatus ?? batch.verification_status,
            update.errorCode ?? null,
            confirmedAt ? new Date(confirmedAt) : null,
            finalizedAt ? new Date(finalizedAt) : null,
            batchId,
          ],
        );
        if (batch.transaction_hash) {
          for (const member of members) {
            await textQuery(
              connection,
              "public chain proof persistence",
              `INSERT INTO public_chain_proofs (
                record_id, batch_id, chain_name, chain_id, block_number,
                block_hash, transaction_hash, transaction_input,
                anchor_address, anchored_at, merkle_root, leaf_index,
                leaf_hash, merkle_protocol, inclusion_path, batch_size,
                verification_status, confirmations, finality_status,
                submitted_at, confirmed_at, finalized_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON DUPLICATE KEY UPDATE
                block_number = VALUES(block_number),
                block_hash = VALUES(block_hash),
                anchored_at = VALUES(anchored_at),
                verification_status = VALUES(verification_status),
                confirmations = VALUES(confirmations),
                finality_status = VALUES(finality_status),
                confirmed_at = VALUES(confirmed_at),
                finalized_at = VALUES(finalized_at)`,
              [
                member.record_id,
                batchId,
                batch.chain_name,
                batch.chain_id,
                update.blockNumber ?? batch.block_number,
                update.blockHash ?? batch.block_hash,
                batch.transaction_hash,
                batch.transaction_input,
                batch.anchor_address,
                update.anchoredAt ? new Date(update.anchoredAt) : null,
                batch.merkle_root,
                member.leaf_index,
                member.leaf_hash,
                batch.merkle_protocol,
                JSON.stringify(parseJsonColumn(member.inclusion_path)),
                batch.leaf_count,
                update.verificationStatus ?? "TRANSACTION_SUBMITTED",
                update.confirmations ?? 0,
                state,
                batch.submitted_at ?? new Date(),
                confirmedAt ? new Date(confirmedAt) : null,
                finalizedAt ? new Date(finalizedAt) : null,
              ],
            );
          }
        }
        await connection.commit();
        return findAnchorBatch(pool, batchId);
      } catch (error) {
        await connection.rollback().catch(() => {});
        throw error;
      } finally {
        connection.release();
      }
    },

    async findById(recordId) {
      const row = await findRow("record_id", recordId);
      return row ? mapRecordRow(row) : null;
    },

    async getBundleById(recordId) {
      const row = await findRow("record_id", recordId);
      if (!row) return null;
      const record = mapRecordRow(row);
      if (record.specimen) {
        return {
          schemaVersion: "sitesealed.specimen-bundle.v1",
          bundleVersion: "SPECIMEN",
          generatedAt: new Date().toISOString(),
          record,
        };
      }
      return createProofBundle(
        record,
        parseEncryptedManifest(row.encrypted_manifest),
      );
    },

    async getEncryptedObjectReferenceById(recordId) {
      const row = await findRow("record_id", recordId);
      if (!row || Boolean(row.is_specimen)) return null;
      return encryptedObjectFromRow(row);
    },

    async healthCheck() {
      await pool.query("SELECT 1");
      return {
        mode: "mysql",
        status: "connected",
        persistent: true,
        writable: true,
      };
    },

    async close() {
      await pool.end();
    },
  };
}

export async function createMysqlRecordStoreFromEnv(environment = process.env) {
  const config = resolveDatabaseConfig(environment);
  if (!config) return null;

  const pool = createDatabasePool(config);
  try {
    await runMigrations(pool);
    const store = createMysqlRecordStore(pool);
    await store.healthCheck();
    return store;
  } catch (error) {
    await pool.end().catch(() => {});
    throw error;
  }
}

export function reconstructReceiptFromRow(row) {
  return createReceiptPayload({
    recordId: row.record_id,
    recordClass: row.record_class,
    recordSha256: row.record_sha256,
    manifestSha256: row.manifest_sha256,
    encryptedObject: encryptedObjectFromRow(row),
    receivedAt: isoTimestamp(row.created_at),
    receiptVersion: row.receipt_version ?? "1.2",
    proofLevel: row.proof_level,
  });
}
