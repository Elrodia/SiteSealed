import { createHash } from "node:crypto";

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
  ...specimenManifest,
  qualifiedAt: "2026-08-10T11:47:09.000Z",
  sha256:
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  manifestSha256: createHash("sha256")
    .update(JSON.stringify(specimenManifest))
    .digest("hex"),
  qualifiedRail: {
    provider: "CertEurope Qualified TSA (simulated)",
    token: "RFC 3161 - serial 00A4-77F2-19C3-8B21",
    status: "Signature valid - CRL check passed (simulated)",
  },
  chainRail: {
    chain: "Ethereum mainnet (simulated)",
    block: "21,904,553",
    anchor: "0x6b1e...9c4d",
    merkleRoot: "4a7c19e2...88f0",
    batchSize: 1024,
    status: "Inclusion path passed (simulated)",
  },
});

export function normalizeRecordId(value) {
  return String(value ?? "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "");
}

export function createMemoryRecordStore() {
  return {
    mode: "memory",
    persistent: false,

    async findById(recordId) {
      return recordId === SPECIMEN_ID ? specimenRecord : null;
    },

    async healthCheck() {
      return {
        mode: "memory",
        status: "not_configured",
        persistent: false,
      };
    },

    async close() {},
  };
}
