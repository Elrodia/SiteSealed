import assert from "node:assert/strict";
import { test } from "node:test";
import {
  MERKLE_PROTOCOL,
  buildMerkleTree,
  merkleLeafHash,
  verifyMerkleProof,
} from "./merkle.js";

function records(count) {
  return Array.from({ length: count }, (_, index) => ({
    recordId: `SR-${index + 1}`,
    evidenceDigest: (index + 1).toString(16).padStart(64, "0"),
  }));
}

test("a one-record batch is independently verifiable", () => {
  const tree = buildMerkleTree(records(1));
  assert.equal(tree.protocol, MERKLE_PROTOCOL);
  assert.equal(tree.root, merkleLeafHash(records(1)[0].evidenceDigest));
  assert.equal(tree.members[0].inclusionPath.length, 0);
  assert.equal(
    verifyMerkleProof({
      evidenceDigest: tree.members[0].evidenceDigest,
      root: tree.root,
      inclusionPath: tree.members[0].inclusionPath,
    }),
    true,
  );
});

test("odd-sized Merkle batches duplicate the final node deterministically", () => {
  const tree = buildMerkleTree(records(5));
  assert.equal(tree.leafCount, 5);
  for (const member of tree.members) {
    assert.equal(
      verifyMerkleProof({
        evidenceDigest: member.evidenceDigest,
        root: tree.root,
        inclusionPath: member.inclusionPath,
      }),
      true,
    );
  }
  const tampered = structuredClone(tree.members[2]);
  tampered.inclusionPath[0].sha256 = "f".repeat(64);
  assert.equal(
    verifyMerkleProof({
      evidenceDigest: tampered.evidenceDigest,
      root: tree.root,
      inclusionPath: tampered.inclusionPath,
    }),
    false,
  );
});
