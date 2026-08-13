import { createHash } from "node:crypto";
import {
  ApiError,
  chainRailFromProof,
  createDevelopmentRecord,
  createProofBundle,
  qualifiedRailFromProof,
  scopeForRecord,
} from "./records.js";

export const SPECIMEN_ID = "SR-2026-08-0147-A3";

const specimenManifest = {
  classification: "Live capture - substructure / site condition",
  project: "Riverside Business Park - Block C",
  description:
    "Standing water in blockwork footings after overnight rainfall - grid A/1-D/4",
  file: "IMG_2417.JPG",
  captureMode: "In-app camera only - gallery import blocked",
  capturedAt: "2026-08-10T11:47:03.000Z",
  position: "50.6412 N, 5.5710 E (+/- 4 m)",
};

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    Object.values(value).forEach(deepFreeze);
  }
  return value;
}

export const specimenRecord = deepFreeze({
  recordId: SPECIMEN_ID,
  specimen: true,
  recordClass: "LIVE_CAPTURE_SPECIMEN",
  proofLevel: "SIMULATED_DUAL_RAIL",
  ...specimenManifest,
  receivedAt: "2026-08-10T11:47:09.000Z",
  qualifiedAt: "2026-08-10T11:47:09.000Z",
  sha256:
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  manifestSha256: createHash("sha256")
    .update(JSON.stringify(specimenManifest))
    .digest("hex"),
  manifestEncryption: "PUBLIC_SPECIMEN",
  receipt: null,
  receiptSha256: null,
  qualifiedRail: {
    state: "SIMULATED",
    provider: "CertEurope Qualified TSA (simulated)",
    token: "RFC 3161 - serial 00A4-77F2-19C3-8B21",
    status: "Signature valid - CRL check passed (simulated)",
  },
  chainRail: {
    state: "SIMULATED",
    chain: "Ethereum mainnet (simulated)",
    block: "21,904,553",
    anchor: "0x6b1e...9c4d",
    merkleRoot: "4a7c19e2...88f0",
    batchSize: 1024,
    status: "Inclusion path passed (simulated)",
  },
});

export function createMemoryRecordStore() {
  const entries = new Map([
    [
      SPECIMEN_ID,
      {
        record: specimenRecord,
        encryptedManifest: null,
        submissionId: null,
      },
    ],
  ]);
  const submissionIndex = new Map();
  const batches = new Map();
  const batchByRecord = new Map();

  return {
    mode: "memory",
    persistent: false,

    async create(input) {
      const existingId = submissionIndex.get(input.submissionId);
      if (existingId) {
        const existing = entries.get(existingId);
        if (
          existing.record.sha256 !== input.recordSha256 ||
          existing.record.manifestSha256 !== input.manifestSha256 ||
          existing.encryptedObject?.ciphertextSha256 !==
            input.encryptedObject.ciphertextSha256 ||
          existing.encryptedObject?.recoveryTokenSha256 !==
            input.encryptedObject.recoveryTokenSha256
        ) {
          throw new ApiError(
            409,
            "SUBMISSION_ID_CONFLICT",
            "This submission ID is already bound to a different encrypted record.",
          );
        }
        return { record: existing.record, created: false };
      }

      const record = createDevelopmentRecord(input, {
        storageProvider: input.storageProvider ?? "MEMORY",
      });
      entries.set(record.recordId, {
        record,
        encryptedManifest: input.encryptedManifest,
        encryptedObject: input.encryptedObject,
        submissionId: input.submissionId,
      });
      submissionIndex.set(input.submissionId, record.recordId);
      return { record, created: true };
    },

    async listTimestampCandidates(limit = 50) {
      return [...entries.values()]
        .map((entry) => entry.record)
        .filter(
          (record) =>
            !record.specimen && record.qualifiedRail?.state === "NOT_ISSUED",
        )
        .slice(0, limit)
        .map((record) => structuredClone(record));
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
      const entry = entries.get(recordId);
      if (!entry || entry.record.specimen) {
        throw new ApiError(404, "RECORD_NOT_FOUND", "Record not found.");
      }
      if (entry.record.qualifiedRail?.state === "SANDBOX_TOKEN_ISSUED") {
        if (entry.record.qualifiedRail.hashedMessage !== proof.hashedMessage) {
          throw new ApiError(
            409,
            "TIMESTAMP_PROOF_CONFLICT",
            "This record already carries a timestamp for another digest.",
          );
        }
        return { created: false, record: structuredClone(entry.record) };
      }
      entry.record = {
        ...entry.record,
        qualifiedAt: proof.certifiedAt,
        qualifiedRail: qualifiedRailFromProof(proof),
      };
      return { created: true, record: structuredClone(entry.record) };
    },

    async listAnchorCandidates(limit = 1024) {
      return [...entries.values()]
        .map((entry) => entry.record)
        .filter(
          (record) =>
            !record.specimen &&
            record.qualifiedRail?.state === "SANDBOX_TOKEN_ISSUED" &&
            record.qualifiedRail.environment === "SANDBOX" &&
            record.qualifiedRail.validatorVersion ===
              "SITESEALED_RFC3161_VALIDATOR_V1" &&
            record.qualifiedRail.signatureVerification === "VALID" &&
            record.qualifiedRail.certificateChainVerification ===
              "VALID_TO_PINNED_SANDBOX_ROOT" &&
            record.qualifiedRail.hashedMessage === record.evidenceDigest &&
            record.chainRail?.state === "NOT_ANCHORED" &&
            !batchByRecord.has(record.recordId),
        )
        .slice(0, limit)
        .map((record) => structuredClone(record));
    },

    async createAnchorBatch(batch) {
      if (batches.has(batch.batchId)) {
        return { created: false, batch: structuredClone(batches.get(batch.batchId)) };
      }
      for (const member of batch.members) {
        if (batchByRecord.has(member.recordId)) {
          throw new ApiError(
            409,
            "ANCHOR_MEMBER_CONFLICT",
            "A record is already assigned to an anchor batch.",
          );
        }
      }
      const stored = {
        ...structuredClone(batch),
        state: "PREPARED",
        chain: "Ethereum mainnet",
        chainId: 1,
        createdAt: new Date().toISOString(),
      };
      batches.set(batch.batchId, stored);
      for (const member of batch.members) {
        batchByRecord.set(member.recordId, batch.batchId);
      }
      return { created: true, batch: structuredClone(stored) };
    },

    async getActionableAnchorBatch() {
      const batch = [...batches.values()].find((candidate) =>
        [
          "PREPARED",
          "SIGNED",
          "SUBMITTED",
          "CONFIRMED",
          "INVALID_ON_CHAIN",
        ].includes(
          candidate.state,
        ),
      );
      return batch ? structuredClone(batch) : null;
    },

    async saveSignedAnchor(batchId, signed) {
      const batch = batches.get(batchId);
      if (!batch) throw new ApiError(404, "ANCHOR_BATCH_NOT_FOUND", "Anchor batch not found.");
      Object.assign(batch, structuredClone(signed), {
        state: "SIGNED",
        signedAt: new Date().toISOString(),
      });
      return structuredClone(batch);
    },

    async markAnchorSubmitted(batchId) {
      const batch = batches.get(batchId);
      if (!batch) throw new ApiError(404, "ANCHOR_BATCH_NOT_FOUND", "Anchor batch not found.");
      batch.state = "SUBMITTED";
      batch.submittedAt ??= new Date().toISOString();
      return structuredClone(batch);
    },

    async updateAnchorBatch(batchId, update) {
      const batch = batches.get(batchId);
      if (!batch) throw new ApiError(404, "ANCHOR_BATCH_NOT_FOUND", "Anchor batch not found.");
      Object.assign(batch, structuredClone(update));
      for (const member of batch.members) {
        const entry = entries.get(member.recordId);
        if (!entry) continue;
        entry.record = {
          ...entry.record,
          chainRail: chainRailFromProof({
            ...batch,
            ...member,
            transactionHash: batch.transactionHash,
            batchId: batch.batchId,
            batchSize: batch.leafCount,
            merkleRoot: batch.root,
            merkleProtocol: batch.protocol,
          }),
        };
      }
      return structuredClone(batch);
    },

    async findById(recordId) {
      return entries.get(recordId)?.record ?? null;
    },

    async getBundleById(recordId) {
      const entry = entries.get(recordId);
      if (!entry) return null;
      if (entry.record.specimen) {
        return {
          schemaVersion: "sitesealed.specimen-bundle.v1",
          bundleVersion: "SPECIMEN",
          generatedAt: new Date().toISOString(),
          record: entry.record,
          scope: scopeForRecord(entry.record),
        };
      }
      return createProofBundle(entry.record, entry.encryptedManifest);
    },

    async getEncryptedObjectReferenceById(recordId) {
      const entry = entries.get(recordId);
      if (!entry || entry.record.specimen) return null;
      return entry.encryptedObject ?? null;
    },

    async healthCheck() {
      return {
        mode: "memory",
        status: "not_configured",
        persistent: false,
        writable: true,
      };
    },

    async close() {},
  };
}
