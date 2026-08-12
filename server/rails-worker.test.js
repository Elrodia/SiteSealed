import assert from "node:assert/strict";
import { test } from "node:test";
import { createMemoryAuditStore } from "./audit.js";
import { createMemoryCoordinator } from "./coordination.js";
import { createDisabledEthereumRail } from "./ethereum.js";
import { verifyMerkleProof } from "./merkle.js";
import {
  deriveEvidencyRuntimeStatus,
  processAnchorQueue,
  processTimestampQueue,
} from "./rails-worker.js";
import { externalProofStatus, validateSealRequest } from "./records.js";
import { createMemoryRecordStore } from "./specimen.js";

function input() {
  return validateSealRequest({
    submissionId: "123e4567-e89b-42d3-a456-426614174000",
    protocolVersion: "1.2",
    recordClass: "IMPORTED_FILE",
    recordSha256: "a".repeat(64),
    manifestSha256: "b".repeat(64),
    encryptedManifest: {
      version: 1,
      algorithm: "AES-256-GCM",
      iv: Buffer.alloc(12, 1).toString("base64"),
      ciphertext: Buffer.alloc(32, 2).toString("base64"),
    },
    encryptedObject: {
      version: 1,
      storageClass: "PRIVATE_CLIENT_ENCRYPTED_ORIGINAL",
      objectKey: `sealed/v1.2/123e4567-e89b-42d3-a456-426614174000/cc/${"c".repeat(64)}.ssenc`,
      algorithm: "AES-256-GCM",
      iv: Buffer.alloc(12, 3).toString("base64"),
      ciphertextSha256: "c".repeat(64),
      ciphertextBytes: 32,
      plaintextBytes: 16,
      recoveryTokenSha256: "d".repeat(64),
    },
  });
}

test("Evidency runtime becomes ON only after an externally returned token", () => {
  const now = () => new Date("2026-08-12T20:00:00.000Z");
  const ready = deriveEvidencyRuntimeStatus({
    configured: true,
    timestamps: { status: "COMPLETED", issued: 0, failed: [], selected: [] },
    now,
  });
  assert.equal(ready.status, "configured");
  assert.equal(ready.externalCallVerified, false);

  const operational = deriveEvidencyRuntimeStatus({
    configured: true,
    timestamps: { status: "COMPLETED", issued: 1, failed: [], selected: [{}] },
    now,
  });
  assert.equal(operational.status, "operational");
  assert.equal(operational.externalCallVerified, true);
  assert.equal(operational.legalUse, false);
  assert.equal(operational.lastSuccessAt, "2026-08-12T20:00:00.000Z");
});

test("dry-run and provider failures can never masquerade as ON", () => {
  const now = () => new Date("2026-08-12T20:05:00.000Z");
  const dryRun = deriveEvidencyRuntimeStatus({
    configured: true,
    dryRun: true,
    timestamps: { status: "DRY_RUN", issued: 0, failed: [], selected: [{}] },
    now,
  });
  assert.equal(dryRun.status, "dry_run_ready");
  assert.equal(dryRun.externalCallVerified, false);

  const failed = deriveEvidencyRuntimeStatus({
    configured: true,
    timestamps: {
      status: "COMPLETED_WITH_ERRORS",
      issued: 0,
      failed: [{ error: "rejected" }],
      selected: [{}],
    },
    previous: {
      status: "operational",
      externalCallVerified: true,
      lastSuccessAt: "2026-08-12T20:00:00.000Z",
    },
    now,
  });
  assert.equal(failed.status, "error");
  assert.equal(failed.externalCallVerified, false);
  assert.equal(failed.lastSuccessAt, "2026-08-12T20:00:00.000Z");
});

test("the timestamp worker persists a test-only token and remains idempotent", async () => {
  const recordStore = createMemoryRecordStore();
  const auditStore = createMemoryAuditStore();
  const coordinator = createMemoryCoordinator();
  const created = await recordStore.create(input());
  const timestampService = {
    configured: true,
    async issueTimestamp({ evidenceDigest }) {
      return {
        provider: "Evidency",
        environment: "SANDBOX",
        legalUse: false,
        qualificationStatus: "TEST_ONLY_NOT_QUALIFIED",
        hashAlgorithm: "SHA256",
        hashedMessage: evidenceDigest,
        serialNumber: "serial-a",
        certifiedAt: "2026-08-12T18:00:00.000Z",
        tokenBase64: Buffer.alloc(64, 9).toString("base64"),
        tokenSha256: "e".repeat(64),
        tsaPolicyId: "1.2.3",
        providerStatus: 0,
        responseValidation: "STATUS_ALGORITHM_AND_DIGEST_BOUND",
        signatureVerification: "NOT_INDEPENDENTLY_VERIFIED",
      };
    },
  };
  const first = await processTimestampQueue({
    recordStore,
    timestampService,
    auditStore,
    coordinator,
  });
  const second = await processTimestampQueue({
    recordStore,
    timestampService,
    auditStore,
    coordinator,
  });
  assert.equal(first.issued, 1);
  assert.equal(second.attempted, 0);
  const record = await recordStore.findById(created.record.recordId);
  assert.equal(record.qualifiedRail.state, "SANDBOX_TOKEN_ISSUED");
  assert.equal(record.qualifiedRail.legalUse, false);
});

test("dry-run previews one exact target without contacting Evidency", async () => {
  const recordStore = createMemoryRecordStore();
  const created = await recordStore.create(input());
  let calls = 0;
  const result = await processTimestampQueue({
    recordStore,
    timestampService: {
      configured: false,
      async issueTimestamp() {
        calls += 1;
      },
    },
    auditStore: createMemoryAuditStore(),
    coordinator: createMemoryCoordinator(),
    targetRecordId: created.record.recordId,
    dryRun: true,
    logger: { info() {} },
  });
  assert.equal(result.status, "DRY_RUN");
  assert.equal(result.attempted, 0);
  assert.equal(result.selected.length, 1);
  assert.equal(result.selected[0].recordId, created.record.recordId);
  assert.equal(calls, 0);
});

test("targeted mode timestamps only the requested eligible record", async () => {
  const recordStore = createMemoryRecordStore();
  const first = await recordStore.create(input());
  const secondInput = input();
  secondInput.submissionId = "223e4567-e89b-42d3-a456-426614174000";
  secondInput.recordSha256 = "1".repeat(64);
  const second = await recordStore.create(secondInput);
  const requested = [];
  const result = await processTimestampQueue({
    recordStore,
    auditStore: createMemoryAuditStore(),
    coordinator: createMemoryCoordinator(),
    targetRecordId: second.record.recordId,
    logger: { info() {} },
    timestampService: {
      configured: true,
      async issueTimestamp({ recordId, evidenceDigest }) {
        requested.push(recordId);
        return {
          provider: "Evidency",
          environment: "SANDBOX",
          legalUse: false,
          qualificationStatus: "TEST_ONLY_NOT_QUALIFIED",
          hashAlgorithm: "SHA256",
          hashedMessage: evidenceDigest,
          serialNumber: "serial-target",
          certifiedAt: "2026-08-12T18:00:00.000Z",
          tokenBase64: Buffer.alloc(64, 7).toString("base64"),
          tokenSha256: "7".repeat(64),
          tsaPolicyId: "1.2.3",
          providerStatus: 0,
          responseValidation: "STATUS_ALGORITHM_AND_DIGEST_BOUND",
          signatureVerification: "NOT_INDEPENDENTLY_VERIFIED",
        };
      },
    },
  });
  assert.deepEqual(requested, [second.record.recordId]);
  assert.equal(result.attempted, 1);
  assert.equal((await recordStore.findById(first.record.recordId)).qualifiedRail.state, "NOT_ISSUED");
});

test("the anchor worker skips safely until mainnet credentials are configured", async () => {
  const result = await processAnchorQueue({
    recordStore: createMemoryRecordStore(),
    ethereumRail: createDisabledEthereumRail(),
    auditStore: createMemoryAuditStore(),
    coordinator: createMemoryCoordinator(),
  });
  assert.equal(result.status, "SKIPPED_NOT_CONFIGURED");
  assert.equal(result.records, 0);
});

test("the worker completes an auditable sandbox-plus-mainnet alpha lifecycle", async () => {
  const recordStore = createMemoryRecordStore();
  const auditStore = createMemoryAuditStore();
  const coordinator = createMemoryCoordinator();
  const created = await recordStore.create(input());
  await processTimestampQueue({
    recordStore,
    auditStore,
    coordinator,
    timestampService: {
      configured: true,
      async issueTimestamp({ evidenceDigest }) {
        return {
          provider: "Evidency",
          environment: "SANDBOX",
          legalUse: false,
          qualificationStatus: "TEST_ONLY_NOT_QUALIFIED",
          hashAlgorithm: "SHA256",
          hashedMessage: evidenceDigest,
          serialNumber: "serial-final",
          certifiedAt: "2026-08-12T18:00:00.000Z",
          tokenBase64: Buffer.alloc(64, 8).toString("base64"),
          tokenSha256: "f".repeat(64),
          tsaPolicyId: "1.2.3",
          providerStatus: 0,
          responseValidation: "STATUS_ALGORITHM_AND_DIGEST_BOUND",
          signatureVerification: "NOT_INDEPENDENTLY_VERIFIED",
        };
      },
    },
  });

  const transactionHash = `0x${"1".repeat(64)}`;
  const anchorAddress = `0x${"2".repeat(40)}`;
  const result = await processAnchorQueue({
    recordStore,
    auditStore,
    coordinator,
    ethereumRail: {
      configured: true,
      async prepareSignedAnchor({ merkleRoot }) {
        return {
          transactionHash,
          signedTransaction: "0xsigned",
          transactionInput: `0x53534c4401${merkleRoot}`,
          anchorAddress,
          nonce: 1,
          maxFeePerGas: "1",
          maxPriorityFeePerGas: "1",
          gasLimit: "30000",
        };
      },
      async broadcastSignedAnchor() {
        return transactionHash;
      },
      async inspectAnchor() {
        return {
          state: "FINALIZED",
          confirmations: 64,
          blockNumber: 100,
          blockHash: `0x${"3".repeat(64)}`,
          anchoredAt: "2026-08-12T18:01:00.000Z",
          finalizedAt: "2026-08-12T18:15:00.000Z",
          verificationStatus: "TRANSACTION_INPUT_AND_SENDER_MATCH",
        };
      },
    },
  });
  assert.equal(result.status, "FINALIZED");
  const record = await recordStore.findById(created.record.recordId);
  assert.equal(record.chainRail.anchor, transactionHash);
  assert.equal(externalProofStatus(record).state, "ALPHA_DUAL_RAIL_COMPLETE");
  assert.equal(externalProofStatus(record).sealed, false);
  assert.equal(
    verifyMerkleProof({
      evidenceDigest: record.evidenceDigest,
      root: record.chainRail.merkleRoot,
      inclusionPath: record.chainRail.inclusionPath,
    }),
    true,
  );
  assert.equal(
    (await auditStore.findByRecordId(record.recordId)).event.eventType,
    "PUBLIC_ANCHOR_RECORDED",
  );
  const second = await processAnchorQueue({
    recordStore,
    auditStore,
    coordinator,
    ethereumRail: { configured: true },
  });
  assert.equal(second.status, "NO_ELIGIBLE_RECORDS");
});
