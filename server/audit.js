import { createHash, randomUUID } from "node:crypto";
import pg from "pg";
import { ApiError, stableStringify } from "./records.js";

const { Pool } = pg;

const AUDIT_EVENT_SCHEMA = "sitesealed.operational-audit-event.v1";
const RECEIPT_EVENT_TYPE = "RECEIPT_RECORDED";
const QUALIFIED_EVENT_TYPE = "QUALIFIED_TIMESTAMP_RECORDED";
const ANCHOR_EVENT_TYPE = "PUBLIC_ANCHOR_RECORDED";
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

const postgresMigrations = [
  {
    id: "001_append_only_evidence_events",
    statements: [
      `CREATE TABLE IF NOT EXISTS sitesealed_evidence_events (
        sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        event_id UUID NOT NULL UNIQUE,
        idempotency_key VARCHAR(180) NOT NULL UNIQUE,
        event_version SMALLINT NOT NULL DEFAULT 1 CHECK (event_version = 1),
        event_type VARCHAR(64) NOT NULL CHECK (event_type IN ('RECEIPT_RECORDED')),
        record_id VARCHAR(64) NOT NULL,
        submission_id UUID NULL,
        payload JSONB NOT NULL,
        payload_sha256 CHAR(64) NOT NULL CHECK (payload_sha256 ~ '^[a-f0-9]{64}$'),
        previous_event_sha256 CHAR(64) NULL CHECK (
          previous_event_sha256 IS NULL OR previous_event_sha256 ~ '^[a-f0-9]{64}$'
        ),
        event_sha256 CHAR(64) NOT NULL UNIQUE CHECK (event_sha256 ~ '^[a-f0-9]{64}$'),
        recorded_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE INDEX IF NOT EXISTS idx_sitesealed_evidence_events_record
        ON sitesealed_evidence_events (record_id, sequence DESC)`,
      `CREATE OR REPLACE FUNCTION sitesealed_reject_audit_mutation()
        RETURNS TRIGGER
        LANGUAGE plpgsql
        AS $$
        BEGIN
          RAISE EXCEPTION 'SiteSealed operational audit events are append-only';
        END;
        $$`,
      `DROP TRIGGER IF EXISTS sitesealed_no_audit_update_delete
        ON sitesealed_evidence_events`,
      `CREATE TRIGGER sitesealed_no_audit_update_delete
        BEFORE UPDATE OR DELETE ON sitesealed_evidence_events
        FOR EACH ROW EXECUTE FUNCTION sitesealed_reject_audit_mutation()`,
      `DROP TRIGGER IF EXISTS sitesealed_no_audit_truncate
        ON sitesealed_evidence_events`,
      `CREATE TRIGGER sitesealed_no_audit_truncate
        BEFORE TRUNCATE ON sitesealed_evidence_events
        FOR EACH STATEMENT EXECUTE FUNCTION sitesealed_reject_audit_mutation()`,
      `COMMENT ON TABLE sitesealed_evidence_events IS
        'Internal append-only, hash-chained operational audit. Not an eIDAS timestamp or public-chain anchor.'`,
    ],
  },
  {
    id: "002_external_proof_events",
    statements: [
      `ALTER TABLE sitesealed_evidence_events
        DROP CONSTRAINT IF EXISTS sitesealed_evidence_events_event_type_check`,
      `ALTER TABLE sitesealed_evidence_events
        ADD CONSTRAINT sitesealed_evidence_events_event_type_check
        CHECK (event_type IN (
          'RECEIPT_RECORDED',
          'QUALIFIED_TIMESTAMP_RECORDED',
          'PUBLIC_ANCHOR_RECORDED'
        ))`,
      `COMMENT ON TABLE sitesealed_evidence_events IS
        'Internal append-only, hash-chained operational audit of receipts and external proof artefacts. The PostgreSQL chain is not itself an eIDAS timestamp or public-chain anchor.'`,
    ],
  },
];

function dependencyMode(environment) {
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

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function resolvePostgresConfig(environment = process.env) {
  const rawUrl = String(environment.DATABASE_URL ?? "").trim();
  if (!rawUrl) {
    if (dependencyMode(environment) === "required") {
      throw new Error(
        "PostgreSQL is required but DATABASE_URL is not configured for this service.",
      );
    }
    return null;
  }

  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("DATABASE_URL must be a valid PostgreSQL connection URL.");
  }
  if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") {
    throw new Error("DATABASE_URL must use the postgres:// or postgresql:// protocol.");
  }
  const database = decodeURIComponent(url.pathname.replace(/^\//, ""));
  if (!url.hostname || !url.username || !database) {
    throw new Error("DATABASE_URL must include a host, user and database name.");
  }

  return {
    url: rawUrl,
    connectionLimit: positiveInteger(environment.POSTGRES_CONNECTION_LIMIT, 5),
  };
}

export function createPostgresPool(config) {
  const pool = new Pool({
    connectionString: config.url,
    max: config.connectionLimit,
    connectionTimeoutMillis: 8_000,
    idleTimeoutMillis: 30_000,
    application_name: "sitesealed-v1.4-alpha.3",
  });
  pool.on("error", (error) => {
    console.error(`PostgreSQL pool error: ${error.message}`);
  });
  return pool;
}

export async function runPostgresMigrations(pool) {
  const client = await pool.connect();
  const applied = [];
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS sitesealed_audit_migrations (
      migration_id VARCHAR(128) PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`);

    await client.query("BEGIN");
    await client.query(
      "LOCK TABLE sitesealed_audit_migrations IN EXCLUSIVE MODE",
    );
    for (const migration of postgresMigrations) {
      const existing = await client.query(
        "SELECT migration_id FROM sitesealed_audit_migrations WHERE migration_id = $1",
        [migration.id],
      );
      if (existing.rowCount > 0) continue;
      for (const statement of migration.statements) {
        await client.query(statement);
      }
      await client.query(
        "INSERT INTO sitesealed_audit_migrations (migration_id) VALUES ($1)",
        [migration.id],
      );
      applied.push(migration.id);
    }
    await client.query("COMMIT");
    return { applied };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

export function receiptAuditPayload(record) {
  return {
    recordId: record.recordId,
    recordClass: record.recordClass,
    proofLevel: record.proofLevel,
    recordSha256: record.sha256,
    manifestSha256: record.manifestSha256,
    receiptSha256: record.receiptSha256,
    encryptedOriginalSha256: record.storage?.ciphertextSha256 ?? null,
    qualifiedTimestampState: record.qualifiedRail?.state ?? "UNKNOWN",
    publicChainState: record.chainRail?.state ?? "UNKNOWN",
  };
}

export function qualifiedTimestampAuditPayload(record, proof) {
  return {
    recordId: record.recordId,
    evidenceDigest: record.evidenceDigest,
    provider: proof.provider,
    environment: proof.environment,
    legalUse: Boolean(proof.legalUse),
    qualificationStatus: proof.qualificationStatus,
    serialNumber: proof.serialNumber,
    certifiedAt: proof.certifiedAt,
    tokenSha256: proof.tokenSha256,
    tsaPolicyId: proof.tsaPolicyId,
    signatureVerification: proof.signatureVerification,
  };
}

export function publicAnchorAuditPayload(record, proof) {
  return {
    recordId: record.recordId,
    evidenceDigest: record.evidenceDigest,
    chain: proof.chain ?? "Ethereum mainnet",
    chainId: Number(proof.chainId ?? 1),
    transactionHash: proof.transactionHash ?? proof.anchor,
    blockNumber: proof.blockNumber ?? null,
    blockHash: proof.blockHash ?? null,
    merkleRoot: proof.merkleRoot,
    leafHash: proof.leafHash,
    leafIndex: proof.leafIndex,
    batchId: proof.batchId,
    finalityStatus: proof.state,
  };
}

export function buildAuditEvent({
  eventId = randomUUID(),
  eventType = RECEIPT_EVENT_TYPE,
  recordId,
  payload,
  previousEventSha256 = null,
  recordedAt = new Date().toISOString(),
}) {
  if (!recordId || !payload || typeof payload !== "object") {
    throw new Error("An audit event requires a record ID and payload.");
  }
  if (
    previousEventSha256 !== null &&
    !SHA256_PATTERN.test(previousEventSha256)
  ) {
    throw new Error("previousEventSha256 must be null or a SHA-256 digest.");
  }

  const payloadSha256 = sha256Hex(stableStringify(payload));
  const preimage = {
    schemaVersion: AUDIT_EVENT_SCHEMA,
    eventId,
    eventType,
    recordId,
    payloadSha256,
    previousEventSha256,
    recordedAt,
  };
  return {
    ...preimage,
    payload,
    eventSha256: sha256Hex(stableStringify(preimage)),
  };
}

export function verifyAuditEvent(event) {
  if (!event || typeof event !== "object") return false;
  const expectedPayloadSha256 = sha256Hex(stableStringify(event.payload));
  if (expectedPayloadSha256 !== event.payloadSha256) return false;
  const preimage = {
    schemaVersion: event.schemaVersion,
    eventId: event.eventId,
    eventType: event.eventType,
    recordId: event.recordId,
    payloadSha256: event.payloadSha256,
    previousEventSha256: event.previousEventSha256 ?? null,
    recordedAt: event.recordedAt,
  };
  return sha256Hex(stableStringify(preimage)) === event.eventSha256;
}

function publicAuditEvent(row) {
  if (!row) return null;
  const event = {
    schemaVersion: AUDIT_EVENT_SCHEMA,
    sequence: String(row.sequence),
    eventId: row.event_id,
    eventType: row.event_type,
    recordId: row.record_id,
    payload: row.payload,
    payloadSha256: row.payload_sha256,
    previousEventSha256: row.previous_event_sha256 ?? null,
    eventSha256: row.event_sha256,
    recordedAt: new Date(row.recorded_at).toISOString(),
  };
  return {
    state: "RECORDED",
    role: "APPLICATION_AUDIT_ONLY",
    independentlyAnchored: false,
    appendOnly: true,
    hashChained: true,
    event,
    eventHashValid: verifyAuditEvent(event),
  };
}

function idempotencyKeyFor(eventType, record, payload) {
  if (eventType === RECEIPT_EVENT_TYPE) return `receipt:${record.recordId}`;
  if (eventType === QUALIFIED_EVENT_TYPE) {
    return `timestamp:${record.recordId}:${payload.tokenSha256}`;
  }
  return `anchor:${record.recordId}:${payload.transactionHash}:${payload.finalityStatus}`;
}

export function createPostgresAuditStore(pool) {
  async function appendEvent({
    eventType,
    record,
    payload,
    submissionId = null,
  }) {
    if (record.specimen) return { created: false, audit: null };
    const payloadSha256 = sha256Hex(stableStringify(payload));
    const idempotencyKey = idempotencyKeyFor(eventType, record, payload);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        "LOCK TABLE sitesealed_evidence_events IN EXCLUSIVE MODE",
      );
      const existing = await client.query(
        `SELECT * FROM sitesealed_evidence_events
          WHERE idempotency_key = $1 LIMIT 1`,
        [idempotencyKey],
      );
      if (existing.rowCount > 0) {
        const row = existing.rows[0];
        if (row.payload_sha256 !== payloadSha256) {
          throw new ApiError(
            409,
            "AUDIT_EVENT_CONFLICT",
            "The PostgreSQL audit event is already bound to different data.",
          );
        }
        await client.query("COMMIT");
        return { created: false, audit: publicAuditEvent(row) };
      }

      const tail = await client.query(
        `SELECT event_sha256 FROM sitesealed_evidence_events
          ORDER BY sequence DESC LIMIT 1`,
      );
      const event = buildAuditEvent({
        eventType,
        recordId: record.recordId,
        payload,
        previousEventSha256: tail.rows[0]?.event_sha256 ?? null,
      });
      const inserted = await client.query(
        `INSERT INTO sitesealed_evidence_events (
          event_id, idempotency_key, event_type, record_id, submission_id,
          payload, payload_sha256, previous_event_sha256, event_sha256,
          recorded_at
        ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10)
        RETURNING *`,
        [
          event.eventId,
          idempotencyKey,
          event.eventType,
          event.recordId,
          submissionId,
          JSON.stringify(event.payload),
          event.payloadSha256,
          event.previousEventSha256,
          event.eventSha256,
          event.recordedAt,
        ],
      );
      await client.query("COMMIT");
      return { created: true, audit: publicAuditEvent(inserted.rows[0]) };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  return {
    mode: "postgresql",
    persistent: true,
    appendOnly: true,
    hashChained: true,

    async appendReceipt(record, { submissionId = null } = {}) {
      return appendEvent({
        eventType: RECEIPT_EVENT_TYPE,
        record,
        payload: receiptAuditPayload(record),
        submissionId,
      });
    },

    async appendQualifiedTimestamp(record, proof) {
      return appendEvent({
        eventType: QUALIFIED_EVENT_TYPE,
        record,
        payload: qualifiedTimestampAuditPayload(record, proof),
      });
    },

    async appendPublicAnchor(record, proof) {
      return appendEvent({
        eventType: ANCHOR_EVENT_TYPE,
        record,
        payload: publicAnchorAuditPayload(record, proof),
      });
    },

    async findByRecordId(recordId) {
      const result = await pool.query(
        `SELECT * FROM sitesealed_evidence_events
          WHERE record_id = $1
          ORDER BY sequence DESC LIMIT 1`,
        [recordId],
      );
      return publicAuditEvent(result.rows[0]);
    },

    async healthCheck() {
      const result = await pool.query(`SELECT
        COALESCE(MAX(sequence), 0)::text AS latest_sequence,
        has_table_privilege(
          current_user,
          'sitesealed_evidence_events',
          'INSERT'
        ) AS can_insert
        FROM sitesealed_evidence_events`);
      return {
        mode: "postgresql",
        status: "connected",
        persistent: true,
        writable: Boolean(result.rows[0]?.can_insert),
        appendOnly: true,
        hashChained: true,
        independentlyAnchored: false,
        latestSequence: result.rows[0]?.latest_sequence ?? "0",
      };
    },

    async close() {
      await pool.end();
    },
  };
}

export function createMemoryAuditStore() {
  const events = [];
  const byIdempotency = new Map();

  async function appendEvent(eventType, record, payload) {
    if (record.specimen) return { created: false, audit: null };
    const key = idempotencyKeyFor(eventType, record, payload);
    const payloadSha256 = sha256Hex(stableStringify(payload));
    const existing = byIdempotency.get(key);
    if (existing) {
      if (existing.event.payloadSha256 !== payloadSha256) {
        throw new ApiError(
          409,
          "AUDIT_EVENT_CONFLICT",
          "The audit event is already bound to different data.",
        );
      }
      return { created: false, audit: existing };
    }
    const event = buildAuditEvent({
      eventType,
      recordId: record.recordId,
      payload,
      previousEventSha256: events.at(-1)?.event.eventSha256 ?? null,
    });
    const audit = {
      state: "RECORDED",
      role: "APPLICATION_AUDIT_ONLY",
      independentlyAnchored: false,
      appendOnly: true,
      hashChained: true,
      event: { ...event, sequence: String(events.length + 1) },
      eventHashValid: verifyAuditEvent(event),
    };
    events.push(audit);
    byIdempotency.set(key, audit);
    return { created: true, audit };
  }

  return {
    mode: "memory",
    persistent: false,
    appendOnly: true,
    hashChained: true,

    async appendReceipt(record) {
      return appendEvent(RECEIPT_EVENT_TYPE, record, receiptAuditPayload(record));
    },

    async appendQualifiedTimestamp(record, proof) {
      return appendEvent(
        QUALIFIED_EVENT_TYPE,
        record,
        qualifiedTimestampAuditPayload(record, proof),
      );
    },

    async appendPublicAnchor(record, proof) {
      return appendEvent(
        ANCHOR_EVENT_TYPE,
        record,
        publicAnchorAuditPayload(record, proof),
      );
    },

    async findByRecordId(recordId) {
      return (
        [...events].reverse().find((item) => item.event.recordId === recordId) ??
        null
      );
    },

    async healthCheck() {
      return {
        mode: "memory",
        status: "not_configured",
        persistent: false,
        writable: true,
        appendOnly: true,
        hashChained: true,
        independentlyAnchored: false,
        latestSequence: String(events.length),
      };
    },

    async close() {},
  };
}

export async function createPostgresAuditStoreFromEnv(
  environment = process.env,
) {
  const config = resolvePostgresConfig(environment);
  if (!config) return null;
  const pool = createPostgresPool(config);
  try {
    await runPostgresMigrations(pool);
    const store = createPostgresAuditStore(pool);
    await store.healthCheck();
    return store;
  } catch (error) {
    await pool.end().catch(() => {});
    throw error;
  }
}
