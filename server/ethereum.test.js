import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { Transaction, Wallet, parseEther, parseUnits } from "ethers";
import {
  createEthereumAnchorClient,
  decodeAnchorCalldata,
  encodeAnchorCalldata,
  resolveEthereumConfig,
} from "./ethereum.js";

const root = "a".repeat(64);

function safeConfig(wallet, overrides = {}) {
  return {
    mode: "mainnet",
    chainId: 1,
    rpcUrl: "https://rpc.example.test",
    privateKey: wallet.privateKey,
    expectedAnchorAddress: wallet.address,
    confirmations: 12,
    maxFeeGwei: 5,
    maxFeePerGas: parseUnits("5", "gwei"),
    maxTransactionFeeEth: "0.00015",
    maxTransactionFeeWei: parseEther("0.00015"),
    gasLimit: 30_000n,
    ...overrides,
  };
}

function safeProvider(overrides = {}) {
  return {
    async getNetwork() {
      return { chainId: 1n };
    },
    async getFeeData() {
      return {
        maxFeePerGas: parseUnits("2", "gwei"),
        maxPriorityFeePerGas: parseUnits("0.5", "gwei"),
      };
    },
    async estimateGas() {
      return 22_000n;
    },
    async getBalance() {
      return parseEther("0.01");
    },
    async getTransactionCount() {
      return 9;
    },
    ...overrides,
  };
}

test("Ethereum calldata is minimal, domain-marked and reversible", () => {
  const data = encodeAnchorCalldata(root);
  assert.equal(data.length, 2 + 10 + 64);
  assert.deepEqual(decodeAnchorCalldata(data), {
    protocol: "SITESEALED_ETHEREUM_CALLDATA_V1",
    merkleRoot: root,
  });
  assert.equal(decodeAnchorCalldata(`0xdeadbeef${root}`), null);
});

test("mainnet mode is opt-in and requires HTTPS, key and expected address", () => {
  const wallet = new Wallet(`0x${"1".padStart(64, "0")}`);
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
        ETHEREUM_ANCHOR_PRIVATE_KEY: wallet.privateKey,
        ETHEREUM_EXPECTED_ANCHOR_ADDRESS: wallet.address,
      }),
    /HTTPS or WSS/,
  );
  assert.throws(
    () =>
      resolveEthereumConfig({
        ETHEREUM_ANCHOR_MODE: "mainnet",
        ETHEREUM_RPC_URL: "https://user:password@rpc.example.test",
        ETHEREUM_ANCHOR_PRIVATE_KEY: wallet.privateKey,
        ETHEREUM_EXPECTED_ANCHOR_ADDRESS: wallet.address,
      }),
    /must not contain HTTP basic-auth credentials/,
  );
  assert.throws(
    () =>
      resolveEthereumConfig({
        ETHEREUM_ANCHOR_MODE: "mainnet",
        ETHEREUM_RPC_URL: "https://rpc.example.test",
        ETHEREUM_ANCHOR_PRIVATE_KEY: wallet.privateKey,
      }),
    /ETHEREUM_EXPECTED_ANCHOR_ADDRESS/,
  );
  const config = resolveEthereumConfig({
    ETHEREUM_ANCHOR_MODE: "mainnet",
    ETHEREUM_RPC_URL: "https://rpc.example.test",
    ETHEREUM_ANCHOR_PRIVATE_KEY: wallet.privateKey,
    ETHEREUM_EXPECTED_ANCHOR_ADDRESS: wallet.address,
  });
  assert.equal(config.maxFeeGwei, 5);
  assert.equal(config.maxTransactionFeeWei, parseEther("0.00015"));
  assert.equal(config.expectedAnchorAddress, wallet.address);
});

test("invalid safety-cap values fail closed instead of falling back", () => {
  const wallet = new Wallet(`0x${"2".padStart(64, "0")}`);
  const environment = {
    ETHEREUM_ANCHOR_MODE: "mainnet",
    ETHEREUM_RPC_URL: "https://rpc.example.test",
    ETHEREUM_ANCHOR_PRIVATE_KEY: wallet.privateKey,
    ETHEREUM_EXPECTED_ANCHOR_ADDRESS: wallet.address,
  };
  assert.throws(
    () => resolveEthereumConfig({ ...environment, ETHEREUM_MAX_FEE_GWEI: "five" }),
    /ETHEREUM_MAX_FEE_GWEI/,
  );
  assert.throws(
    () => resolveEthereumConfig({ ...environment, ETHEREUM_MAX_TX_FEE_ETH: "0" }),
    /ETHEREUM_MAX_TX_FEE_ETH/,
  );
});

test("the expected address must match the locally held signing key", () => {
  const wallet = new Wallet(`0x${"3".padStart(64, "0")}`);
  const other = new Wallet(`0x${"4".padStart(64, "0")}`);
  assert.throws(
    () =>
      createEthereumAnchorClient(
        safeConfig(wallet, { expectedAnchorAddress: other.address }),
        { provider: safeProvider(), wallet },
      ),
    /not ETHEREUM_EXPECTED_ANCHOR_ADDRESS/,
  );
});

test("dry-run preview performs read-only network, gas, fee and balance checks", async () => {
  const wallet = new Wallet(`0x${"5".padStart(64, "0")}`);
  let nonceReads = 0;
  const client = createEthereumAnchorClient(safeConfig(wallet), {
    wallet,
    provider: safeProvider({
      async getTransactionCount() {
        nonceReads += 1;
        return 9;
      },
    }),
  });
  const preview = await client.previewAnchor({ merkleRoot: root });
  assert.equal(preview.anchorAddress, wallet.address);
  assert.equal(preview.estimatedGas, "22000");
  assert.equal(preview.maximumAuthorizedFeeWei, "60000000000000");
  assert.equal(nonceReads, 0);
  assert.equal("signedTransaction" in preview, false);
});

test("the anchor client signs and locally revalidates a capped self-transaction", async () => {
  const wallet = new Wallet(`0x${"6".padStart(64, "0")}`);
  const client = createEthereumAnchorClient(safeConfig(wallet), {
    provider: safeProvider(),
    wallet,
  });
  const prepared = await client.prepareSignedAnchor({ merkleRoot: root });
  const parsed = Transaction.from(prepared.signedTransaction);
  assert.match(prepared.transactionHash, /^0x[a-f0-9]{64}$/);
  assert.equal(prepared.transactionHash, parsed.hash);
  assert.equal(prepared.transactionInput, encodeAnchorCalldata(root));
  assert.equal(prepared.anchorAddress, wallet.address);
  assert.equal(prepared.nonce, 9);
  assert.equal(parsed.chainId, 1n);
  assert.equal(parsed.from, wallet.address);
  assert.equal(parsed.to, wallet.address);
  assert.equal(parsed.value, 0n);
});

test("a signer returning a different transaction is rejected before persistence", async () => {
  const expected = new Wallet(`0x${"7".padStart(64, "0")}`);
  const attacker = new Wallet(`0x${"8".padStart(64, "0")}`);
  const misleadingWallet = {
    address: expected.address,
    async signTransaction(transaction) {
      return attacker.signTransaction(transaction);
    },
  };
  const client = createEthereumAnchorClient(safeConfig(expected), {
    provider: safeProvider(),
    wallet: misleadingWallet,
  });
  await assert.rejects(
    client.prepareSignedAnchor({ merkleRoot: root }),
    /does not match the authorized mainnet anchor/,
  );
});

test("fee, gas, transaction-cost and balance caps each fail closed", async (t) => {
  const wallet = new Wallet(`0x${"9".padStart(64, "0")}`);
  await t.test("fee cap", async () => {
    const client = createEthereumAnchorClient(safeConfig(wallet), {
      wallet,
      provider: safeProvider({
        async getFeeData() {
          return {
            maxFeePerGas: parseUnits("6", "gwei"),
            maxPriorityFeePerGas: parseUnits("1", "gwei"),
          };
        },
      }),
    });
    await assert.rejects(client.previewAnchor({ merkleRoot: root }), /5 gwei cap/);
  });
  await t.test("gas limit", async () => {
    const client = createEthereumAnchorClient(safeConfig(wallet), {
      wallet,
      provider: safeProvider({ async estimateGas() { return 30_001n; } }),
    });
    await assert.rejects(client.previewAnchor({ merkleRoot: root }), /estimated gas/);
  });
  await t.test("absolute transaction fee", async () => {
    const client = createEthereumAnchorClient(
      safeConfig(wallet, { maxTransactionFeeWei: parseEther("0.00001") }),
      { wallet, provider: safeProvider() },
    );
    await assert.rejects(
      client.previewAnchor({ merkleRoot: root }),
      /transaction cap/,
    );
  });
  await t.test("wallet balance", async () => {
    const client = createEthereumAnchorClient(safeConfig(wallet), {
      wallet,
      provider: safeProvider({ async getBalance() { return 1n; } }),
    });
    await assert.rejects(
      client.previewAnchor({ merkleRoot: root }),
      /balance is insufficient/,
    );
  });
});

test("nonce-too-low recovery requires the exact signed transaction to be visible", async () => {
  const wallet = new Wallet(`0x${"a".padStart(64, "0")}`);
  const signedTransaction = await wallet.signTransaction({
    type: 2,
    chainId: 1,
    nonce: 0,
    to: wallet.address,
    value: 0n,
    data: encodeAnchorCalldata(root),
    gasLimit: 30_000n,
    maxFeePerGas: parseUnits("2", "gwei"),
    maxPriorityFeePerGas: parseUnits("0.5", "gwei"),
  });
  const expectedHash = Transaction.from(signedTransaction).hash;
  const batch = {
    signedTransaction,
    transactionHash: expectedHash,
    merkleRoot: root,
    anchorAddress: wallet.address,
    nonce: 0,
    maxFeePerGas: parseUnits("2", "gwei").toString(),
    maxPriorityFeePerGas: parseUnits("0.5", "gwei").toString(),
    gasLimit: "30000",
  };
  let known = true;
  const provider = safeProvider({
    async broadcastTransaction() {
      const error = new Error("nonce too low");
      error.shortMessage = "nonce too low";
      throw error;
    },
    async getTransaction(hash) {
      return known && hash === expectedHash ? { hash } : null;
    },
  });
  const client = createEthereumAnchorClient(safeConfig(wallet), {
    provider,
    wallet,
  });
  assert.equal(
    await client.broadcastSignedAnchor(batch),
    expectedHash,
  );
  known = false;
  await assert.rejects(
    client.broadcastSignedAnchor(batch),
    /nonce too low/,
  );
});

test("a persisted signed transaction is revalidated before every broadcast", async () => {
  const wallet = new Wallet(`0x${"c".padStart(64, "0")}`);
  let broadcasts = 0;
  const client = createEthereumAnchorClient(safeConfig(wallet), {
    wallet,
    provider: safeProvider({
      async broadcastTransaction() {
        broadcasts += 1;
        return { hash: `0x${"d".repeat(64)}` };
      },
    }),
  });
  const prepared = await client.prepareSignedAnchor({ merkleRoot: root });
  await assert.rejects(
    client.broadcastSignedAnchor({
      ...prepared,
      merkleRoot: "b".repeat(64),
    }),
    /does not match the authorized mainnet anchor/,
  );
  assert.equal(broadcasts, 0);
});

test("mainnet inspection verifies calldata, sender, receipt and finalized block", async () => {
  const wallet = new Wallet(`0x${"b".padStart(64, "0")}`);
  const transactionHash = `0x${"6".repeat(64)}`;
  const blockHash = `0x${"7".repeat(64)}`;
  const provider = safeProvider({
    async getTransaction() {
      return {
        chainId: 1n,
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
  });
  const client = createEthereumAnchorClient(safeConfig(wallet), {
    provider,
    wallet,
  });
  const inspected = await client.inspectAnchor({
    transactionHash,
    merkleRoot: root,
    anchorAddress: wallet.address,
  });
  assert.equal(inspected.state, "FINALIZED");
  assert.equal(inspected.blockHash, blockHash);
  assert.equal(inspected.confirmations, 13);
  assert.equal(inspected.onChainBindingVerified, true);
  assert.equal(inspected.finalityVerified, true);
  assert.equal(inspected.verificationStatus, "TRANSACTION_INPUT_AND_SENDER_MATCH");
});

test("pending mempool fields cannot create a terminal binding mismatch", async () => {
  const wallet = new Wallet(`0x${"c".padStart(64, "0")}`);
  const transactionHash = `0x${"8".repeat(64)}`;
  let transactionReads = 0;
  const client = createEthereumAnchorClient(safeConfig(wallet), {
    wallet,
    provider: safeProvider({
      async getTransactionReceipt() {
        return null;
      },
      async getTransaction() {
        transactionReads += 1;
        return {
          chainId: 0n,
          data: "0x",
          from: wallet.address,
          to: null,
        };
      },
    }),
  });

  const inspected = await client.inspectAnchor({
    transactionHash,
    merkleRoot: root,
    anchorAddress: wallet.address,
  });

  assert.equal(inspected.state, "SUBMITTED");
  assert.equal(inspected.onChainBindingVerified, false);
  assert.equal(inspected.finalityVerified, false);
  assert.equal(inspected.verificationStatus, "TRANSACTION_PENDING_RECEIPT");
  assert.equal(transactionReads, 0);
});

test("close() survives a WebSocket torn down mid-handshake (teardown-during-handshake)", async () => {
  const wallet = new Wallet(`0x${"a".padStart(64, "0")}`);
  const socket = new EventEmitter();

  const provider = {
    websocket: socket,
    async getNetwork() {
      return { chainId: 1n };
    },
    async getBlockNumber() {
      return 1;
    },
    async destroy() {
      // Mirror emitErrorAndClose: emit asynchronously, outside the promise chain.
      await new Promise((resolve) => setImmediate(resolve));
      socket.emit("error", new Error("WebSocket was closed before the connection was established"));
    },
  };

  const client = createEthereumAnchorClient(safeConfig(wallet), { provider, wallet });

  // Guard against any unhandled 'error' escaping to the process level.
  const uncaughtErrors = [];
  function onUncaught(err) {
    uncaughtErrors.push(err);
  }
  process.on("uncaughtExceptionMonitor", onUncaught);

  try {
    await assert.doesNotReject(() => client.close());
    // Give the event loop a tick so any async emission fires before we assert.
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(uncaughtErrors, [], "no unhandled error must escape close()");
  } finally {
    process.removeListener("uncaughtExceptionMonitor", onUncaught);
  }
});

test("close() works cleanly when the provider has no websocket property (JsonRpcProvider shape)", async () => {
  const wallet = new Wallet(`0x${"b".padStart(64, "0")}`);

  const provider = {
    // No websocket property — mirrors JsonRpcProvider.
    async getNetwork() {
      return { chainId: 1n };
    },
    async getBlockNumber() {
      return 2;
    },
    async destroy() {},
  };

  const client = createEthereumAnchorClient(safeConfig(wallet), { provider, wallet });
  await assert.doesNotReject(() => client.close());
});

test("close() does not propagate a destroy() rejection", async () => {
  const wallet = new Wallet(`0x${"c".padStart(64, "0")}`);

  const provider = {
    async getNetwork() {
      return { chainId: 1n };
    },
    async getBlockNumber() {
      return 3;
    },
    async destroy() {
      throw new Error("destroy failed");
    },
  };

  const client = createEthereumAnchorClient(safeConfig(wallet), { provider, wallet });
  await assert.doesNotReject(() => client.close());
});
