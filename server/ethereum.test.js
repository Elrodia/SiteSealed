import assert from "node:assert/strict";
import { test } from "node:test";
import { Wallet, parseUnits } from "ethers";
import {
  createEthereumAnchorClient,
  decodeAnchorCalldata,
  encodeAnchorCalldata,
  resolveEthereumConfig,
} from "./ethereum.js";

const root = "a".repeat(64);

test("Ethereum calldata is minimal, domain-marked and reversible", () => {
  const data = encodeAnchorCalldata(root);
  assert.equal(data.length, 2 + 10 + 64);
  assert.deepEqual(decodeAnchorCalldata(data), {
    protocol: "SITESEALED_ETHEREUM_CALLDATA_V1",
    merkleRoot: root,
  });
  assert.equal(decodeAnchorCalldata(`0xdeadbeef${root}`), null);
});

test("mainnet mode is opt-in and refuses incomplete or non-HTTPS configuration", () => {
  assert.equal(resolveEthereumConfig({}), null);
  assert.throws(
    () => resolveEthereumConfig({ ETHEREUM_ANCHOR_MODE: "mainnet" }),
    /ETHEREUM_RPC_URL and ETHEREUM_ANCHOR_PRIVATE_KEY/,
  );
  assert.throws(
    () =>
      resolveEthereumConfig({
        ETHEREUM_ANCHOR_MODE: "mainnet",
        ETHEREUM_RPC_URL: "http://rpc.example.test",
        ETHEREUM_ANCHOR_PRIVATE_KEY: "1".padStart(64, "0"),
      }),
    /HTTPS or WSS/,
  );
});

test("the anchor client signs a capped Ethereum mainnet self-transaction", async () => {
  const wallet = new Wallet(`0x${"1".padStart(64, "0")}`);
  const provider = {
    async getNetwork() {
      return { chainId: 1n };
    },
    async getFeeData() {
      return {
        maxFeePerGas: parseUnits("25", "gwei"),
        maxPriorityFeePerGas: parseUnits("1", "gwei"),
      };
    },
    async getTransactionCount() {
      return 9;
    },
  };
  const client = createEthereumAnchorClient(
    {
      mode: "mainnet",
      chainId: 1,
      rpcUrl: "https://rpc.example.test",
      privateKey: wallet.privateKey,
      confirmations: 12,
      maxFeeGwei: 60,
      gasLimit: 30_000n,
    },
    { provider, wallet },
  );
  const prepared = await client.prepareSignedAnchor({ merkleRoot: root });
  assert.match(prepared.transactionHash, /^0x[a-f0-9]{64}$/);
  assert.equal(prepared.transactionInput, encodeAnchorCalldata(root));
  assert.equal(prepared.anchorAddress, wallet.address);
  assert.equal(prepared.nonce, 9);
  assert.match(prepared.signedTransaction, /^0x/);
});

test("the configured fee cap prevents an unexpectedly expensive transaction", async () => {
  const wallet = new Wallet(`0x${"2".padStart(64, "0")}`);
  const client = createEthereumAnchorClient(
    {
      mode: "mainnet",
      chainId: 1,
      rpcUrl: "https://rpc.example.test",
      privateKey: wallet.privateKey,
      confirmations: 12,
      maxFeeGwei: 10,
      gasLimit: 30_000n,
    },
    {
      wallet,
      provider: {
        async getNetwork() {
          return { chainId: 1n };
        },
        async getFeeData() {
          return {
            maxFeePerGas: parseUnits("11", "gwei"),
            maxPriorityFeePerGas: parseUnits("1", "gwei"),
          };
        },
        async getTransactionCount() {
          return 0;
        },
      },
    },
  );
  await assert.rejects(
    client.prepareSignedAnchor({ merkleRoot: root }),
    /exceeds the configured 10 gwei cap/,
  );
});

test("nonce-too-low recovery requires the exact signed transaction to be visible", async () => {
  const wallet = new Wallet(`0x${"3".padStart(64, "0")}`);
  const expectedHash = `0x${"4".repeat(64)}`;
  let known = true;
  const provider = {
    async broadcastTransaction() {
      const error = new Error("nonce too low");
      error.shortMessage = "nonce too low";
      throw error;
    },
    async getTransaction(hash) {
      return known && hash === expectedHash ? { hash } : null;
    },
  };
  const client = createEthereumAnchorClient(
    {
      mode: "mainnet",
      chainId: 1,
      rpcUrl: "https://rpc.example.test",
      privateKey: wallet.privateKey,
      confirmations: 12,
      maxFeeGwei: 60,
      gasLimit: 30_000n,
    },
    { provider, wallet },
  );
  assert.equal(
    await client.broadcastSignedAnchor("0xsigned", expectedHash),
    expectedHash,
  );
  known = false;
  await assert.rejects(
    client.broadcastSignedAnchor("0xsigned", expectedHash),
    /nonce too low/,
  );
});

test("mainnet inspection verifies calldata, sender, receipt and finalized block", async () => {
  const wallet = new Wallet(`0x${"5".padStart(64, "0")}`);
  const transactionHash = `0x${"6".repeat(64)}`;
  const blockHash = `0x${"7".repeat(64)}`;
  const provider = {
    async getNetwork() {
      return { chainId: 1n };
    },
    async getTransaction() {
      return {
        data: encodeAnchorCalldata(root),
        from: wallet.address,
        to: wallet.address,
      };
    },
    async getTransactionReceipt() {
      return { status: 1, blockNumber: 100, blockHash };
    },
    async getBlockNumber() {
      return 112;
    },
    async getBlock(tag) {
      if (tag === "finalized") return { number: 105 };
      return { number: 100, timestamp: 1_786_507_200 };
    },
  };
  const client = createEthereumAnchorClient(
    {
      mode: "mainnet",
      chainId: 1,
      rpcUrl: "https://rpc.example.test",
      privateKey: wallet.privateKey,
      confirmations: 12,
      maxFeeGwei: 60,
      gasLimit: 30_000n,
    },
    { provider, wallet },
  );
  const inspected = await client.inspectAnchor({
    transactionHash,
    merkleRoot: root,
    anchorAddress: wallet.address,
  });
  assert.equal(inspected.state, "FINALIZED");
  assert.equal(inspected.blockHash, blockHash);
  assert.equal(inspected.confirmations, 13);
  assert.equal(inspected.verificationStatus, "TRANSACTION_INPUT_AND_SENDER_MATCH");
});
