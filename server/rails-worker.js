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
import { RFC3161_VALIDATOR_VERSION } from "./rfc3161.js";
import { createMemoryRecordStore } from "./specimen.js";
import {
  createMemoryObjectStore,
  createS3ObjectStoreFromEnv,
} from "./storage.js";

const VALID_CERTIFICATE_CHAIN = "VALID_TO_PINNED_SANDBOX_ROOT";

export function operationalErrorMessage(error) {
  return String(error?.message ?? "External rail operation failed.").replace(
    /\b((?:https?|wss?):\/\/[^/\s'"<>?#]+)([/?#][^\s'"<>]*)?/gi,
    (_match, origin) => `${origin}/[redacted]`,
  );
}

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function exactlyOne(value, variableName) {
  const normalized = String(value ?? "1").trim();
  if (normalized !== "1") {
    throw new Error(`${variableName} must remain exactly 1 in alpha.8.`);
  }
  return 1;
}

function booleanFlag(value, fallback = false, variableName = "BOOLEAN_FLAG") {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (!normalized) return fallback;
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  throw new Error(`${variableName} must be true or false.`);
}

function optionalRecordId(value, variableName = "TARGET_RECORD_ID") {
  const recordId = String(value ?? "").trim();
  if (!recordId) return null;
  if (!/^SR-[A-Z0-9-]{8,80}$/i.test(recordId)) {
    throw new Error(`${variableName} is not a valid SiteSealed record ID.`);
  }
  return recordId;
}

function independentlyVerifiedTimestamp(record) {
  const proof = record?.qualifiedRail;
  return Boolean(
    record &&
      !record.specimen &&
      proof?.state === "SANDBOX_TOKEN_ISSUED" &&
      proof.environment === "SANDBOX" &&
      proof.validatorVersion === RFC3161_VALIDATOR_VERSION &&
      proof.signatureVerification === "VALID" &&
      proof.certificateChainVerification === VALID_CERTIFICATE_CHAIN &&
      proof.hashedMessage === record.evidenceDigest,
  );
}

function independentlyVerifiedAnchorCandidate(record) {
  return Boolean(
    independentlyVerifiedTimestamp(record) &&
      record.chainRail?.state === "NOT_ANCHORED",
  );
}

export async function processStorageOrphans({
  objectStore,
  coordinator,
  ttlMs = 24 * 60 * 60 * 1000,
  limit = 1000,
  now = () => Date.now(),
} = {}) {
  const release = await coordinator.acquireJobLock("storage-orphan-reaper", {
    ttlMs: 10 * 60 * 1000,
  });
  if (!release) {
    return {
      status: "SKIPPED_LOCKED",
      scanned: 0,
      deleted: 0,
      deletedBytes: 0,
    };
  }
  try {
    return objectStore.cleanupStagedObjects({
      olderThan: new Date(now() - ttlMs),
      limit,
    });
  } finally {
    await release();
  }
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
  const verified = Number(timestamps.verified ?? 0);
  const previouslyVerified =
    previous?.status === "operational" &&
    previous?.externalCallVerified === true &&
    previous?.validatorVersion === RFC3161_VALIDATOR_VERSION &&
    previous?.signatureVerification === "VALID" &&
    previous?.certificateChainVerification === VALID_CERTIFICATE_CHAIN &&
    Boolean(previous?.lastSuccessAt);
  const targetAlreadyVerified =
    timestamps.targetState === "SANDBOX_TOKEN_ISSUED" &&
    timestamps.targetSignatureVerification === "VALID" &&
    timestamps.targetCertificateChainVerification === VALID_CERTIFICATE_CHAIN;

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
  } else if (issued > 0 && verified === issued) {
    status = "operational";
    message = "A sandbox RFC 3161 token passed independent CMS signature and pinned-chain verification, then was stored.";
    lastSuccessAt = checkedAt;
  } else if (previouslyVerified || targetAlreadyVerified) {
    status = "operational";
    message = "The worker is healthy and an independently verified sandbox token is already recorded.";
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
        ? "RFC3161_CMS_SIGNATURE_CHAIN_AND_DIGEST_VALID"
        : "NOT_YET_EXTERNALLY_VERIFIED",
    signatureVerification:
      status === "operational" ? "VALID" : "NOT_YET_VERIFIED",
    certificateChainVerification:
      status === "operational"
        ? VALID_CERTIFICATE_CHAIN
        : "NOT_YET_VERIFIED",
    validatorVersion: RFC3161_VALIDATOR_VERSION,
    revocationVerification: "NOT_CHECKED",
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
  let verified = 0;
  try {
    let candidates;
    let targetState = null;
    let targetSignatureVerification = null;
    let targetCertificateChainVerification = null;
    if (targetRecordId) {
      const target = await recordStore.findById(targetRecordId);
      targetState = target?.qualifiedRail?.state ?? "NOT_FOUND";
      targetSignatureVerification =
        target?.qualifiedRail?.signatureVerification ?? null;
      targetCertificateChainVerification =
        target?.qualifiedRail?.certificateChainVerification ?? null;
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
        targetSignatureVerification,
        targetCertificateChainVerification,
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
        if (
          proof?.validatorVersion !== RFC3161_VALIDATOR_VERSION ||
          proof?.signatureVerification !== "VALID" ||
          proof?.certificateChainVerification !== VALID_CERTIFICATE_CHAIN ||
          proof?.hashedMessage !== record.evidenceDigest
        ) {
          throw new Error(
            "The timestamp proof did not pass the required independent RFC 3161 verification gate.",
          );
        }
        const stored = await recordStore.saveQualifiedTimestamp(
          record.recordId,
          proof,
        );
        await auditStore.appendQualifiedTimestamp(stored.record, proof);
        await coordinator.deleteCachedRecord(record.recordId);
        issued += stored.created ? 1 : 0;
        verified += stored.created ? 1 : 0;
        logger.info?.("SiteSealed Evidency request completed", {
          recordId: record.recordId,
          issued: stored.created,
          environment: proof.environment,
          qualificationStatus: proof.qualificationStatus,
          tokenSha256: proof.tokenSha256,
          signatureVerification: proof.signatureVerification,
          certificateChainVerification:
            proof.certificateChainVerification,
          validatorVersion: proof.validatorVersion,
        });
      } catch (error) {
        failed.push({
          recordId: record.recordId,
          error: operationalErrorMessage(error),
        });
      }
    }
    return {
      status: failed.length > 0 ? "COMPLETED_WITH_ERRORS" : "COMPLETED",
      attempted: candidates.length,
      issued,
      verified,
      failed,
      selected,
      targetState,
      targetSignatureVerification,
      targetCertificateChainVerification,
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
  targetRecordId = null,
  dryRun = false,
  maxTransactionsPerRun = 1,
  logger = console,
} = {}) {
  if (!ethereumRail?.configured) {
    return {
      status: "SKIPPED_NOT_CONFIGURED",
      batchId: null,
      records: 0,
      selected: [],
      transactionsSigned: 0,
      transactionsBroadcast: 0,
    };
  }
  if (maxTransactionsPerRun !== 1) {
    throw new Error(
      "ETHEREUM_MAX_TRANSACTIONS_PER_RUN must remain exactly 1 in alpha.8.",
    );
  }
  const release = await coordinator.acquireJobLock("ethereum-mainnet-anchor", {
    ttlMs: 30 * 60 * 1000,
  });
  if (!release) {
    return {
      status: "SKIPPED_LOCKED",
      batchId: null,
      records: 0,
      selected: [],
      transactionsSigned: 0,
      transactionsBroadcast: 0,
    };
  }
  try {
    let batch = await recordStore.getActionableAnchorBatch();
    if (batch) {
      const memberRecords = await Promise.all(
        batch.members.map((member) => recordStore.findById(member.recordId)),
      );
      if (!memberRecords.every(independentlyVerifiedTimestamp)) {
        return {
          status: "INELIGIBLE_ACTIONABLE_BATCH",
          batchId: batch.batchId,
          records: batch.leafCount,
          selected: batch.members.map(({ recordId, evidenceDigest }) => ({
            recordId,
            evidenceDigest,
          })),
          transactionsSigned: 0,
          transactionsBroadcast: 0,
        };
      }
    }
    if (
      batch &&
      targetRecordId &&
      (batch.members.length !== 1 ||
        batch.members[0].recordId !== targetRecordId)
    ) {
      return {
        status: "TARGET_MISMATCH_ACTIONABLE_BATCH",
        batchId: batch.batchId,
        records: batch.leafCount,
        selected: batch.members.map(({ recordId, evidenceDigest }) => ({
          recordId,
          evidenceDigest,
        })),
        transactionsSigned: 0,
        transactionsBroadcast: 0,
      };
    }

    let targetState = null;
    let candidates = [];
    if (!batch) {
      if (targetRecordId) {
        const target = await recordStore.findById(targetRecordId);
        targetState = target?.chainRail?.state ?? "NOT_FOUND";
        candidates = independentlyVerifiedAnchorCandidate(target) ? [target] : [];
      } else {
        candidates = (await recordStore.listAnchorCandidates(maxBatchSize)).filter(
          independentlyVerifiedAnchorCandidate,
        );
      }
      if (candidates.length === 0) {
        return {
          status: dryRun
            ? "DRY_RUN_NO_ELIGIBLE_RECORD"
            : "NO_ELIGIBLE_RECORDS",
          batchId: null,
          records: 0,
          selected: [],
          targetState,
          transactionsSigned: 0,
          transactionsBroadcast: 0,
        };
      }
      const tree = buildMerkleTree(
        candidates.map((record) => ({
          recordId: record.recordId,
          evidenceDigest: record.evidenceDigest,
        })),
      );
      const selected = tree.members.map(({ recordId, evidenceDigest }) => ({
        recordId,
        evidenceDigest,
      }));
      logger.info?.("SiteSealed Ethereum selection", {
        dryRun,
        targeted: Boolean(targetRecordId),
        selected,
        merkleRoot: tree.root,
      });
      if (dryRun) {
        const preview = await ethereumRail.previewAnchor({ merkleRoot: tree.root });
        return {
          status: "DRY_RUN",
          batchId: null,
          records: tree.leafCount,
          selected,
          targetState,
          merkleRoot: tree.root,
          preview,
          transactionsSigned: 0,
          transactionsBroadcast: 0,
        };
      }
      const created = await recordStore.createAnchorBatch({
        batchId: randomUUID(),
        ...tree,
      });
      batch = created.batch;
    }

    const selected = batch.members.map(({ recordId, evidenceDigest }) => ({
      recordId,
      evidenceDigest,
    }));
    if (dryRun) {
      const preview =
        batch.state === "PREPARED"
          ? await ethereumRail.previewAnchor({ merkleRoot: batch.root })
          : null;
      return {
        status: "DRY_RUN_ACTIONABLE_BATCH",
        actionableState: batch.state,
        batchId: batch.batchId,
        records: batch.leafCount,
        selected,
        targetState,
        merkleRoot: batch.root,
        transactionHash: batch.transactionHash ?? null,
        preview,
        transactionsSigned: 0,
        transactionsBroadcast: 0,
      };
    }

    let transactionsSigned = 0;
    let transactionsBroadcast = 0;
    if (batch.state === "PREPARED") {
      const signed = await ethereumRail.prepareSignedAnchor({
        merkleRoot: batch.root,
      });
      batch = await recordStore.saveSignedAnchor(batch.batchId, signed);
      transactionsSigned = 1;
    }
    if (batch.state === "SIGNED") {
      await ethereumRail.broadcastSignedAnchor({
        ...batch,
        merkleRoot: batch.root,
      });
      batch = await recordStore.markAnchorSubmitted(batch.batchId);
      transactionsBroadcast = 1;
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
      selected,
      transactionHash: batch.transactionHash,
      confirmations: batch.confirmations,
      anchorAddress: batch.anchorAddress,
      onChainBindingVerified: Boolean(inspection.onChainBindingVerified),
      finalityVerified: Boolean(inspection.finalityVerified),
      finalizedAt: inspection.finalizedAt ?? batch.finalizedAt ?? null,
      transactionsSigned,
      transactionsBroadcast,
    };
  } finally {
    await release();
  }
}

export function deriveEthereumRuntimeStatus({
  configured = false,
  dryRun = false,
  anchors = {},
  previous = null,
  targetRecordId = null,
  anchorAddress = null,
  now = () => new Date(),
} = {}) {
  const checkedAt = now().toISOString();
  const previousFinalized =
    previous?.status === "finalized" &&
    previous?.chainId === 1 &&
    previous?.onChainBindingVerified === true &&
    previous?.finalityVerified === true &&
    /^0x[a-f0-9]{64}$/i.test(String(previous?.transactionHash ?? ""));
  const failed = [
    "FAILED_ON_CHAIN",
    "INVALID_ON_CHAIN",
    "INELIGIBLE_ACTIONABLE_BATCH",
    "TARGET_MISMATCH_ACTIONABLE_BATCH",
    "ERROR",
  ].includes(anchors.status);
  let status;
  let message;
  let lastSubmittedAt = previous?.lastSubmittedAt ?? null;
  let lastFinalizedAt = previous?.lastFinalizedAt ?? null;

  if (!configured) {
    status = "not_configured";
    message = "The Ethereum mainnet anchor worker is disabled.";
  } else if (failed) {
    status = "error";
    message = "The latest Ethereum mainnet execution failed closed.";
  } else if (dryRun) {
    status =
      anchors.status === "DRY_RUN_NO_ELIGIBLE_RECORD"
        ? "dry_run_no_eligible_record"
        : "dry_run_ready";
    message =
      status === "dry_run_ready"
        ? "The selected anchor passed read-only RPC, gas, fee and balance checks; no transaction was signed or broadcast."
        : "Ethereum dry-run completed without an eligible target record.";
  } else if (anchors.status === "FINALIZED") {
    status = "finalized";
    message = "The Ethereum mainnet transaction binding and finalized block were independently checked.";
    lastSubmittedAt ??= checkedAt;
    lastFinalizedAt = anchors.finalizedAt ?? checkedAt;
  } else if (anchors.status === "CONFIRMED") {
    status = "confirmed";
    message = "The Ethereum mainnet transaction is confirmed and awaiting finalized-block verification.";
    lastSubmittedAt ??= checkedAt;
  } else if (["SUBMITTED", "SIGNED", "PREPARED"].includes(anchors.status)) {
    status = anchors.status === "SUBMITTED" ? "submitted" : "configured";
    message =
      anchors.status === "SUBMITTED"
        ? "The exact signed transaction was submitted and is awaiting confirmations."
        : "The Ethereum mainnet worker is configured and has not finalized an anchor yet.";
    if (anchors.status === "SUBMITTED") lastSubmittedAt ??= checkedAt;
  } else if (previousFinalized) {
    status = "finalized";
    message = "No new eligible receipt was found; the latest verified mainnet anchor remains finalized.";
  } else {
    status = "configured";
    message = "Ethereum mainnet controls are loaded; no finalized anchor is recorded yet.";
  }

  const transactionHash =
    anchors.transactionHash ??
    (status === "finalized" ? previous?.transactionHash ?? null : null);
  const effectiveAnchorAddress =
    anchors.anchorAddress ?? anchorAddress ?? previous?.anchorAddress ?? null;
  const carryingPreviousFinalizedAnchor =
    status === "finalized" && anchors.status !== "FINALIZED";
  return {
    mode: configured ? "ethereum" : "disabled",
    status,
    network: "Ethereum mainnet",
    chainId: 1,
    configured: Boolean(configured),
    writesEnabled: Boolean(configured && !dryRun),
    dryRun: Boolean(dryRun),
    targetRecordId,
    anchorAddress: effectiveAnchorAddress,
    transactionHash,
    batchId: anchors.batchId ?? (status === "finalized" ? previous?.batchId ?? null : null),
    records: Number(
      carryingPreviousFinalizedAnchor
        ? previous?.records ?? 0
        : anchors.records ?? 0,
    ),
    confirmations: Number(
      carryingPreviousFinalizedAnchor
        ? previous?.confirmations ?? 0
        : anchors.confirmations ?? 0,
    ),
    onChainBindingVerified:
      status === "finalized"
        ? Boolean(anchors.onChainBindingVerified ?? previous?.onChainBindingVerified)
        : Boolean(anchors.onChainBindingVerified),
    finalityVerified:
      status === "finalized"
        ? Boolean(anchors.finalityVerified ?? previous?.finalityVerified)
        : false,
    transactionsSigned: Number(anchors.transactionsSigned ?? 0),
    transactionsBroadcast: Number(anchors.transactionsBroadcast ?? 0),
    lastCheckedAt: checkedAt,
    lastSubmittedAt,
    lastFinalizedAt,
    message,
  };
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

async function publishEthereumRuntimeStatus({
  coordinator,
  ethereumRail,
  anchors,
  dryRun,
  targetRecordId,
  ttlMs,
}) {
  const previous = await coordinator.getRailRuntimeStatus("ethereum");
  const runtime = deriveEthereumRuntimeStatus({
    configured: ethereumRail?.configured,
    dryRun,
    anchors,
    previous,
    targetRecordId,
    anchorAddress: ethereumRail?.address ?? null,
  });
  runtime.expectedAnchorAddress = ethereumRail?.expectedAnchorAddress ?? null;
  runtime.maxFeeGwei = ethereumRail?.maxFeeGwei ?? null;
  runtime.maxTransactionFeeEth =
    ethereumRail?.maxTransactionFeeEth ?? null;
  runtime.gasLimit = ethereumRail?.gasLimit ?? null;
  runtime.freshUntil = new Date(
    new Date(runtime.lastCheckedAt).valueOf() + ttlMs,
  ).toISOString();
  return coordinator.setRailRuntimeStatus("ethereum", runtime, { ttlMs });
}

export async function runRailsWorker(environment = process.env) {
  let recordStore;
  let objectStore;
  let auditStore;
  let coordinator;
  let timestampService;
  let ethereumRail;
  try {
    recordStore =
      (await createMysqlRecordStoreFromEnv(environment)) ??
      createMemoryRecordStore();
    objectStore =
      (await createS3ObjectStoreFromEnv(environment)) ??
      createMemoryObjectStore();
    auditStore =
      (await createPostgresAuditStoreFromEnv(environment)) ??
      createMemoryAuditStore();
    coordinator =
      (await createRedisCoordinatorFromEnv(environment)) ??
      createMemoryCoordinator();
    const storageCleanup = await processStorageOrphans({
      objectStore,
      coordinator,
      ttlMs:
        Math.min(
          positiveInteger(environment.STAGING_OBJECT_TTL_HOURS, 24),
          24 * 30,
        ) *
        60 *
        60 *
        1000,
      limit: Math.min(
        positiveInteger(environment.STAGING_REAPER_MAX_OBJECTS, 1000),
        10000,
      ),
    });
    timestampService = createEvidencyTimestampServiceFromEnv(environment);
    try {
      ethereumRail = createEthereumAnchorClientFromEnv(environment);
      await ethereumRail.healthCheck();
      await ethereumRail.probeRpc();
    } catch (error) {
      const lastCheckedAt = new Date().toISOString();
      const ttlMs =
        Math.min(
          positiveInteger(environment.ETHEREUM_RUNTIME_STATUS_TTL_SECONDS, 90_000),
          7 * 24 * 60 * 60,
        ) * 1000;
      await coordinator
        .setRailRuntimeStatus(
          "ethereum",
          {
            mode: "ethereum",
            status: "error",
            network: "Ethereum mainnet",
            chainId: 1,
            configured: false,
            writesEnabled: false,
            dryRun: true,
            onChainBindingVerified: false,
            finalityVerified: false,
            lastCheckedAt,
            freshUntil: new Date(
              new Date(lastCheckedAt).valueOf() + ttlMs,
            ).toISOString(),
            message: "Ethereum mainnet configuration failed closed.",
          },
          { ttlMs },
        )
        .catch(() => {});
      throw error;
    }

    const targetRecordId = optionalRecordId(
      environment.EVIDENCY_TARGET_RECORD_ID,
      "EVIDENCY_TARGET_RECORD_ID",
    );
    const dryRun = booleanFlag(
      environment.EVIDENCY_DRY_RUN,
      false,
      "EVIDENCY_DRY_RUN",
    );
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
        failed: [{ error: operationalErrorMessage(error) }],
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
    const ethereumTargetRecordId = optionalRecordId(
      environment.ETHEREUM_TARGET_RECORD_ID,
      "ETHEREUM_TARGET_RECORD_ID",
    );
    const ethereumDryRun = booleanFlag(
      environment.ETHEREUM_DRY_RUN,
      true,
      "ETHEREUM_DRY_RUN",
    );
    const maxTransactionsPerRun = exactlyOne(
      environment.ETHEREUM_MAX_TRANSACTIONS_PER_RUN,
      "ETHEREUM_MAX_TRANSACTIONS_PER_RUN",
    );
    const ethereumStatusTtlMs =
      Math.min(
        positiveInteger(environment.ETHEREUM_RUNTIME_STATUS_TTL_SECONDS, 90_000),
        7 * 24 * 60 * 60,
      ) * 1000;
    let anchors;
    let ethereumRuntime;
    try {
      anchors = await processAnchorQueue({
        recordStore,
        ethereumRail,
        auditStore,
        coordinator,
        maxBatchSize: Math.min(
          positiveInteger(environment.ANCHOR_MAX_BATCH_SIZE, 1),
          1024,
        ),
        targetRecordId: ethereumTargetRecordId,
        dryRun: ethereumDryRun,
        maxTransactionsPerRun,
      });
      ethereumRuntime = await publishEthereumRuntimeStatus({
        coordinator,
        ethereumRail,
        anchors,
        dryRun: ethereumDryRun,
        targetRecordId: ethereumTargetRecordId,
        ttlMs: ethereumStatusTtlMs,
      });
    } catch (error) {
      const failedAnchors = {
        status: "ERROR",
        batchId: null,
        records: 0,
        transactionsSigned: 0,
        transactionsBroadcast: 0,
      };
      await publishEthereumRuntimeStatus({
        coordinator,
        ethereumRail,
        anchors: failedAnchors,
        dryRun: ethereumDryRun,
        targetRecordId: ethereumTargetRecordId,
        ttlMs: ethereumStatusTtlMs,
      }).catch(() => {});
      throw error;
    }
    const workerFailed =
      timestamps.failed.length > 0 ||
      [
        "FAILED_ON_CHAIN",
        "INVALID_ON_CHAIN",
        "INELIGIBLE_ACTIONABLE_BATCH",
        "TARGET_MISMATCH_ACTIONABLE_BATCH",
      ].includes(anchors.status);
    return {
      ok: !workerFailed,
      timestamps,
      anchors,
      storageCleanup,
      runtime: { evidency: evidencyRuntime, ethereum: ethereumRuntime },
    };
  } finally {
    await Promise.all([
      recordStore?.close().catch(() => {}),
      objectStore?.close().catch(() => {}),
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
      console.error(
        `SiteSealed rail worker failed: ${operationalErrorMessage(error)}`,
      );
      process.exitCode = 1;
    });
}
