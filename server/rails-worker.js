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

export async function processTimestampQueue({
  recordStore,
  timestampService,
  auditStore,
  coordinator,
  limit = 50,
} = {}) {
  if (!timestampService?.configured) {
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
    const candidates = await recordStore.listTimestampCandidates(limit);
    for (const record of candidates) {
      try {
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
      } catch (error) {
        failed.push({ recordId: record.recordId, error: error.message });
      }
    }
    return {
      status: failed.length > 0 ? "COMPLETED_WITH_ERRORS" : "COMPLETED",
      attempted: candidates.length,
      issued,
      failed,
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
      limit: positiveInteger(environment.EVIDENCY_BATCH_SIZE, 50),
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
