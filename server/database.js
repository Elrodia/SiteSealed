import mysql from "mysql2/promise";
import {
  ApiError,
  createDevelopmentRecord,
  createProofBundle,
  createReceiptPayload,
  parseEncryptedManifest,
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
      },
    );
    return {
      ...record,
      manifestEncryption:
        row.manifest_encryption ?? "AES-256-GCM / client-held key",
      receiptSha256: row.receipt_sha256 ?? record.receiptSha256,
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
  qualified.token_reference,
  qualified.certified_at,
  qualified.verification_status AS qualified_status,
  chain_proof.chain_name,
  chain_proof.block_number,
  chain_proof.transaction_hash,
  chain_proof.merkle_root,
  chain_proof.batch_size,
  chain_proof.verification_status AS chain_status
FROM sealed_records AS records
LEFT JOIN qualified_timestamp_proofs AS qualified
  ON qualified.record_id = records.record_id
LEFT JOIN public_chain_proofs AS chain_proof
  ON chain_proof.record_id = records.record_id`;

export function createMysqlRecordStore(pool) {
  async function findRow(column, value) {
    const allowedColumns = new Set(["record_id", "submission_id"]);
    if (!allowedColumns.has(column)) throw new Error("Unsupported lookup column.");
    const [rows] = await pool.execute(
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
              record_class, proof_level, receipt_sha256, client_protocol,
              storage_provider, storage_object_key, storage_cipher_sha256,
              storage_cipher_iv, storage_cipher_bytes, storage_plaintext_bytes,
              storage_recovery_token_sha256, storage_status,
              record_status, is_specimen, created_at, updated_at
            ) VALUES (
              ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?,
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
  });
}
