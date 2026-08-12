import "./load-env.js";
import { randomUUID } from "node:crypto";
import {
  createMemoryAuditStore,
  createPostgresAuditStoreFromEnv,
} from "./audit.js";
import {
  createMemoryCoordinator,
  createRedisCoordinatorFromEnv,
} from "./coordination.js";
import { createMysqlRecordStoreFromEnv } from "./database.js";
import {
  createEvidencyTimestampServiceFromEnv,
} from "./evidency.js";
import { createEthereumAnchorClientFromEnv } from "./ethereum.js";
import { buildMerkleTree } from "./merkle.js";
import { createMemoryRecordStore } from "./specimen.js";

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function booleanFlag(value, fallback = false) {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (!normalized) return fallback;
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  throw new Error("EVIDENCY_DRY_RUN must be true or false.");
}

function optionalRecordId(value) {
  const recordId = String(value ?? "").trim();
  if (!recordId) return null;
  if (!/^SR-[A-Z0-9-]{8,80}$/i.test(recordId)) {
    throw new Error("EVIDENCY_TARGET_RECORD_ID is not a valid SiteSealed record ID.");
  }
  return recordId;
}

export function deriveEvidencyRuntimeStatus({
  configured = false,
  dryRun = false,
  timestamps = {},
  previous = null,
  now = () => new Date(),
} = {}) {
  const checkedAt = now().toISOString();
  const selectedCount = Array.isArray(timestamps.selected)
    ? timestamps.selected.length
    : 0;
  const failures = Array.isArray(timestamps.failed) ? timestamps.failed : [];
  const issued = Number(timestamps.issued ?? 0);
  const previouslyVerified =
    previous?.status === "operational" &&
    previous?.externalCallVerified === true &&
    Boolean(previous?.lastSuccessAt);
  const targetAlreadyIssued =
    timestamps.targetState === "SANDBOX_TOKEN_ISSUED";

  let status;
  let message;
  let lastSuccessAt = previous?.lastSuccessAt ?? null;

  if (!configured && !dryRun) {
    status = "not_configured";
    message = "The Evidency sandbox worker is disabled.";
  } else if (dryRun) {
    status = selectedCount > 0 ? "dry_run_ready" : "dry_run_no_eligible_record";
    message =
      selectedCount > 0
        ? "The exact record is selected; no Evidency request was sent."
        : "Dry-run completed without an eligible target record.";
  } else if (failures.length > 0 || timestamps.status === "FAILED") {
    status = "error";
    message = "The latest Evidency sandbox execution failed.";
  } else if (issued > 0) {
    status = "operational";
    message = "A sandbox RFC 3161 token was received, digest-bound and stored.";
    lastSuccessAt = checkedAt;
  } else if (previouslyVerified || targetAlreadyIssued) {
    status = "operational";
    message = "The worker is healthy and a sandbox token has been verified previously.";
    lastSuccessAt ??= checkedAt;
  } else {
    status = "configured";
    message = "Sandbox credentials are loaded; no successful token is recorded yet.";
  }

  return {
    mode: configured ? "evidency" : "disabled",
    status,
    provider: "Evidency",
    environment: "SANDBOX",
    configured: Boolean(configured),
    externalCallVerified: status === "operational",
    legalUse: false,
    qualificationStatus: "TEST_ONLY_NOT_QUALIFIED",
    responseValidation:
      status === "operational"
        ? "TOKEN_RECEIVED_DIGEST_BOUND_AND_STORED"
        : "NOT_YET_EXTERNALLY_VERIFIED",
    dryRun: Boolean(dryRun),
    lastCheckedAt: checkedAt,
    lastSuccessAt,
    message,
  };
}

export async function processTimestampQueue({
  recordStore,
  timestampService,
  auditStore,
  coordinator,
  limit = 50,
  targetRecordId = null,
  dryRun = false,
  logger = console,
} = {}) {
  if (!timestampService?.configured && !dryRun) {
    return { status: "SKIPPED_NOT_CONFIGURED", attempted: 0, issued: 0, failed: [] };
  }
  const release = await coordinator.acquireJobLock("evidency-timestamp", {
    ttlMs: 10 * 60 * 1000,
  });
  if (!release) {
    return { status: "SKIPPED_LOCKED", attempted: 0, issued: 0, failed: [] };
  }
  const failed = [];
  let issued = 0;
  try {
    let candidates;
    let targetState = null;
    if (targetRecordId) {
      const target = await recordStore.findById(targetRecordId);
      targetState = target?.qualifiedRail?.state ?? "NOT_FOUND";
      const eligible =
        target &&
        !target.specimen &&
        target.qualifiedRail?.state === "NOT_ISSUED";
      candidates = eligible ? [target] : [];
    } else {
      candidates = await recordStore.listTimestampCandidates(limit);
    }

    const selected = candidates.map((record) => ({
      recordId: record.recordId,
      evidenceDigest: record.evidenceDigest,
    }));
    logger.info?.("SiteSealed Evidency selection", {
      dryRun,
      targeted: Boolean(targetRecordId),
      selected,
    });

    if (dryRun) {
      return {
        status: candidates.length > 0 ? "DRY_RUN" : "DRY_RUN_NO_ELIGIBLE_RECORD",
        attempted: 0,
        issued: 0,
        failed: [],
        selected,
        targetState,
      };
    }

    for (const record of candidates) {
      try {
        logger.info?.("SiteSealed Evidency request starting", {
          recordId: record.recordId,
          evidenceDigest: record.evidenceDigest,
        });
        const proof = await timestampService.issueTimestamp({
          recordId: record.recordId,
          evidenceDigest: record.evidenceDigest,
        });
        const stored = await recordStore.saveQualifiedTimestamp(
          record.recordId,
          proof,
        );
        await auditStore.appendQualifiedTimestamp(stored.record, proof);
        await coordinator.deleteCachedRecord(record.recordId);
        issued += stored.created ? 1 : 0;
        logger.info?.("SiteSealed Evidency request completed", {
          recordId: record.recordId,
          issued: stored.created,
          environment: proof.environment,
          qualificationStatus: proof.qualificationStatus,
          tokenSha256: proof.tokenSha256,
        });
      } catch (error) {
        failed.push({ recordId: record.recordId, error: error.message });
      }
    }
    return {
      status: failed.length > 0 ? "COMPLETED_WITH_ERRORS" : "COMPLETED",
      attempted: candidates.length,
      issued,
      failed,
      selected,
      targetState,
    };
  } finally {
    await release();
  }
}

export async function processAnchorQueue({
  recordStore,
  ethereumRail,
  auditStore,
  coordinator,
  maxBatchSize = 1024,
} = {}) {
  if (!ethereumRail?.configured) {
    return { status: "SKIPPED_NOT_CONFIGURED", batchId: null, records: 0 };
  }
  const release = await coordinator.acquireJobLock("ethereum-mainnet-anchor", {
    ttlMs: 30 * 60 * 1000,
  });
  if (!release) {
    return { status: "SKIPPED_LOCKED", batchId: null, records: 0 };
  }
  try {
    let batch = await recordStore.getActionableAnchorBatch();
    if (!batch) {
      const candidates = await recordStore.listAnchorCandidates(maxBatchSize);
      if (candidates.length === 0) {
        return { status: "NO_ELIGIBLE_RECORDS", batchId: null, records: 0 };
      }
      const tree = buildMerkleTree(
        candidates.map((record) => ({
          recordId: record.recordId,
          evidenceDigest: record.evidenceDigest,
        })),
      );
      const created = await recordStore.createAnchorBatch({
        batchId: randomUUID(),
        ...tree,
      });
      batch = created.batch;
    }

    if (batch.state === "PREPARED") {
      const signed = await ethereumRail.prepareSignedAnchor({
        merkleRoot: batch.root,
      });
      batch = await recordStore.saveSignedAnchor(batch.batchId, signed);
    }
    if (batch.state === "SIGNED") {
      await ethereumRail.broadcastSignedAnchor(
        batch.signedTransaction,
        batch.transactionHash,
      );
      batch = await recordStore.markAnchorSubmitted(batch.batchId);
    }

    const stateBeforeInspection = batch.state;
    const inspection = await ethereumRail.inspectAnchor({
      ...batch,
      merkleRoot: batch.root,
    });
    const isAuditableTransition =
      ["CONFIRMED", "FINALIZED"].includes(inspection.state) &&
      inspection.state !== stateBeforeInspection;
    if (isAuditableTransition) {
      for (const member of batch.members) {
        const record = await recordStore.findById(member.recordId);
        const proof = {
          ...batch,
          ...inspection,
          ...member,
          chain: "Ethereum mainnet",
          chainId: 1,
          transactionHash: batch.transactionHash,
          merkleRoot: batch.root,
          merkleProtocol: batch.protocol,
          batchSize: batch.leafCount,
        };
        await auditStore.appendPublicAnchor(record, proof);
      }
    }
    batch = await recordStore.updateAnchorBatch(batch.batchId, inspection);
    if (isAuditableTransition) {
      for (const member of batch.members) {
        await coordinator.deleteCachedRecord(member.recordId);
      }
    }
    return {
      status: batch.state,
      batchId: batch.batchId,
      records: batch.leafCount,
      transactionHash: batch.transactionHash,
      confirmations: batch.confirmations,
    };
  } finally {
    await release();
  }
}

async function publishEvidencyRuntimeStatus({
  coordinator,
  timestampService,
  timestamps,
  dryRun,
  ttlMs,
}) {
  const previous = await coordinator.getRailRuntimeStatus("evidency");
  const runtime = deriveEvidencyRuntimeStatus({
    configured: timestampService?.configured,
    dryRun,
    timestamps,
    previous,
  });
  runtime.freshUntil = new Date(
    new Date(runtime.lastCheckedAt).valueOf() + ttlMs,
  ).toISOString();
  return coordinator.setRailRuntimeStatus("evidency", runtime, { ttlMs });
}

export async function runRailsWorker(environment = process.env) {
  let recordStore;
  let auditStore;
  let coordinator;
  let timestampService;
  let ethereumRail;
  try {
    recordStore =
      (await createMysqlRecordStoreFromEnv(environment)) ??
      createMemoryRecordStore();
    auditStore =
      (await createPostgresAuditStoreFromEnv(environment)) ??
      createMemoryAuditStore();
    coordinator =
      (await createRedisCoordinatorFromEnv(environment)) ??
      createMemoryCoordinator();
    timestampService = createEvidencyTimestampServiceFromEnv(environment);
    ethereumRail = createEthereumAnchorClientFromEnv(environment);

    const targetRecordId = optionalRecordId(
      environment.EVIDENCY_TARGET_RECORD_ID,
    );
    const dryRun = booleanFlag(environment.EVIDENCY_DRY_RUN, false);
    const statusTtlMs =
      Math.min(
        positiveInteger(environment.EVIDENCY_RUNTIME_STATUS_TTL_SECONDS, 90_000),
        7 * 24 * 60 * 60,
      ) * 1000;
    let timestamps;
    let evidencyRuntime;
    try {
      timestamps = await processTimestampQueue({
        recordStore,
        timestampService,
        auditStore,
        coordinator,
        limit: Math.min(
          positiveInteger(environment.EVIDENCY_BATCH_SIZE, 50),
          positiveInteger(environment.EVIDENCY_MAX_REQUESTS_PER_RUN, 1),
        ),
        targetRecordId,
        dryRun,
      });
      evidencyRuntime = await publishEvidencyRuntimeStatus({
        coordinator,
        timestampService,
        timestamps,
        dryRun,
        ttlMs: statusTtlMs,
      });
    } catch (error) {
      const failedTimestamps = {
        status: "FAILED",
        attempted: 0,
        issued: 0,
        failed: [{ error: error.message }],
        selected: [],
      };
      await publishEvidencyRuntimeStatus({
        coordinator,
        timestampService,
        timestamps: failedTimestamps,
        dryRun,
        ttlMs: statusTtlMs,
      }).catch(() => {});
      throw error;
    }
    const anchors = await processAnchorQueue({
      recordStore,
      ethereumRail,
      auditStore,
      coordinator,
      maxBatchSize: positiveInteger(environment.ANCHOR_MAX_BATCH_SIZE, 1024),
    });
    const workerFailed =
      timestamps.failed.length > 0 ||
      ["FAILED_ON_CHAIN", "INVALID_ON_CHAIN"].includes(anchors.status);
    return {
      ok: !workerFailed,
      timestamps,
      anchors,
      runtime: { evidency: evidencyRuntime },
    };
  } finally {
    await Promise.all([
      recordStore?.close().catch(() => {}),
      auditStore?.close().catch(() => {}),
      coordinator?.close().catch(() => {}),
      timestampService?.close().catch(() => {}),
      ethereumRail?.close().catch(() => {}),
    ]);
  }
}

if (import.meta.url === new URL(process.argv[1], "file:").href) {
  runRailsWorker()
    .then((result) => {
      console.log(JSON.stringify(result));
      if (!result.ok) process.exitCode = 1;
    })
    .catch((error) => {
      console.error(`SiteSealed rail worker failed: ${error.message}`);
      process.exitCode = 1;
    });
}
