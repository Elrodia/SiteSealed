import mysql from "mysql2/promise";
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
    record_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    manifest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    encrypted_manifest LONGBLOB NULL,
    manifest_encryption VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    specimen_payload JSON NULL,
    record_status VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    is_specimen TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (record_id),
    INDEX idx_sealed_records_record_sha256 (record_sha256),
    INDEX idx_sealed_records_manifest_sha256 (manifest_sha256)
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

const migrations = [
  {
    id: "001_genesis_evidence_records",
    async up(connection) {
      for (const statement of schemaStatements) {
        await connection.query(statement);
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
        record_id, record_sha256, manifest_sha256, encrypted_manifest,
        manifest_encryption, specimen_payload, record_status, is_specimen
      ) VALUES (?, ?, ?, NULL, ?, ?, ?, ?)`,
      [
        record.recordId,
        record.sha256,
        record.manifestSha256,
        "PUBLIC_SPECIMEN",
        specimenPayload,
        "SEALED_SPECIMEN",
        1,
      ],
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
  if (value instanceof Date) return value.toISOString();
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? null : parsed.toISOString();
}

export function mapRecordRow(row) {
  const specimenPayload =
    typeof row.specimen_payload === "string"
      ? JSON.parse(row.specimen_payload)
      : row.specimen_payload ?? {};

  return {
    recordId: row.record_id,
    specimen: Boolean(row.is_specimen),
    classification: specimenPayload.classification ?? "Encrypted manifest",
    project: specimenPayload.project ?? "Private project",
    description:
      specimenPayload.description ??
      "Capture metadata remains encrypted under a client-held key.",
    file: specimenPayload.file ?? "Encrypted original",
    captureMode: specimenPayload.captureMode ?? "Attested capture",
    capturedAt: isoTimestamp(specimenPayload.capturedAt),
    qualifiedAt: isoTimestamp(row.certified_at),
    position: specimenPayload.position ?? "Encrypted in capture manifest",
    sha256: row.record_sha256,
    manifestSha256: row.manifest_sha256,
    qualifiedRail: {
      provider: row.qualified_provider,
      token: row.token_reference,
      status: row.qualified_status,
    },
    chainRail: {
      chain: row.chain_name,
      block:
        row.block_number === null
          ? "Pending"
          : Number(row.block_number).toLocaleString("en-US"),
      anchor: row.transaction_hash,
      merkleRoot: row.merkle_root,
      batchSize: Number(row.batch_size),
      status: row.chain_status,
    },
  };
}

export function createMysqlRecordStore(pool) {
  return {
    mode: "mysql",
    persistent: true,

    async findById(recordId) {
      const [rows] = await pool.execute(
        `SELECT
          records.record_id,
          records.record_sha256,
          records.manifest_sha256,
          records.specimen_payload,
          records.is_specimen,
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
        INNER JOIN qualified_timestamp_proofs AS qualified
          ON qualified.record_id = records.record_id
        INNER JOIN public_chain_proofs AS chain_proof
          ON chain_proof.record_id = records.record_id
        WHERE records.record_id = ?
          AND records.record_status IN ('SEALED', 'SEALED_SPECIMEN')
        LIMIT 1`,
        [recordId],
      );

      return rows.length > 0 ? mapRecordRow(rows[0]) : null;
    },

    async healthCheck() {
      await pool.query("SELECT 1");
      return {
        mode: "mysql",
        status: "connected",
        persistent: true,
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
