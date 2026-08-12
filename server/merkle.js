import { createHash } from "node:crypto";

export const MERKLE_PROTOCOL = "SITESEALED_MERKLE_SHA256_V1";

const SHA256_PATTERN = /^[a-f0-9]{64}$/;

function sha256Buffer(value) {
  return createHash("sha256").update(value).digest();
}

function digestBytes(value, label) {
  const digest = String(value ?? "").trim().toLowerCase();
  if (!SHA256_PATTERN.test(digest)) {
    throw new Error(`${label} must be a hexadecimal SHA-256 digest.`);
  }
  return Buffer.from(digest, "hex");
}

export function merkleLeafHash(evidenceDigest) {
  return sha256Buffer(
    Buffer.concat([Buffer.from([0x00]), digestBytes(evidenceDigest, "evidenceDigest")]),
  ).toString("hex");
}

export function merkleParentHash(left, right) {
  return sha256Buffer(
    Buffer.concat([
      Buffer.from([0x01]),
      digestBytes(left, "left"),
      digestBytes(right, "right"),
    ]),
  ).toString("hex");
}

export function buildMerkleTree(records) {
  if (!Array.isArray(records) || records.length === 0) {
    throw new Error("At least one record is required to build a Merkle tree.");
  }

  const normalized = records.map((record, index) => {
    const recordId = String(record?.recordId ?? "").trim();
    if (!recordId) throw new Error(`Record ${index} has no recordId.`);
    const evidenceDigest = String(record?.evidenceDigest ?? "")
      .trim()
      .toLowerCase();
    digestBytes(evidenceDigest, `records[${index}].evidenceDigest`);
    return {
      recordId,
      evidenceDigest,
      leafHash: merkleLeafHash(evidenceDigest),
      leafIndex: index,
    };
  });

  const paths = normalized.map(() => []);
  let level = normalized.map((item, index) => ({
    hash: item.leafHash,
    members: [index],
  }));

  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] ?? left;
      for (const member of left.members) {
        paths[member].push({ position: "right", sha256: right.hash });
      }
      if (right !== left) {
        for (const member of right.members) {
          paths[member].push({ position: "left", sha256: left.hash });
        }
      }
      next.push({
        hash: merkleParentHash(left.hash, right.hash),
        members: right === left ? [...left.members] : [...left.members, ...right.members],
      });
    }
    level = next;
  }

  return {
    protocol: MERKLE_PROTOCOL,
    root: level[0].hash,
    leafCount: normalized.length,
    members: normalized.map((item, index) => ({
      ...item,
      inclusionPath: paths[index],
    })),
  };
}

export function verifyMerkleProof({ evidenceDigest, root, inclusionPath }) {
  digestBytes(root, "root");
  if (!Array.isArray(inclusionPath)) return false;
  let current = merkleLeafHash(evidenceDigest);
  for (const step of inclusionPath) {
    if (!step || (step.position !== "left" && step.position !== "right")) {
      return false;
    }
    try {
      digestBytes(step.sha256, "inclusionPath.sha256");
    } catch {
      return false;
    }
    current =
      step.position === "left"
        ? merkleParentHash(step.sha256, current)
        : merkleParentHash(current, step.sha256);
  }
  return current === String(root).toLowerCase();
}
