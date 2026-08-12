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
    if (targetRecordId) {
      const target = await recordStore.findById(targetRecordId);
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

    const timestamps = await processTimestampQueue({
      recordStore,
      timestampService,
      auditStore,
      coordinator,
      limit: Math.min(
        positiveInteger(environment.EVIDENCY_BATCH_SIZE, 50),
        positiveInteger(environment.EVIDENCY_MAX_REQUESTS_PER_RUN, 1),
      ),
      targetRecordId: optionalRecordId(environment.EVIDENCY_TARGET_RECORD_ID),
      dryRun: booleanFlag(environment.EVIDENCY_DRY_RUN, false),
    });
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
    return { ok: !workerFailed, timestamps, anchors };
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
