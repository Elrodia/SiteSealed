import {
  JsonRpcProvider,
  WebSocketProvider,
  Wallet,
  formatUnits,
  getBytes,
  keccak256,
  parseUnits,
} from "ethers";

export const ETHEREUM_MAINNET_CHAIN_ID = 1;
export const ANCHOR_CALLDATA_MAGIC = "53534c4401";
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const PRIVATE_KEY_PATTERN = /^(?:0x)?[a-f0-9]{64}$/i;

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function positiveNumber(value, fallback) {
  const parsed = Number.parseFloat(String(value ?? ""));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function encodeAnchorCalldata(merkleRoot) {
  const root = String(merkleRoot ?? "").trim().toLowerCase();
  if (!SHA256_PATTERN.test(root)) {
    throw new Error("merkleRoot must be a hexadecimal SHA-256 digest.");
  }
  return `0x${ANCHOR_CALLDATA_MAGIC}${root}`;
}

export function decodeAnchorCalldata(data) {
  const normalized = String(data ?? "").trim().toLowerCase();
  const expectedLength = 2 + ANCHOR_CALLDATA_MAGIC.length + 64;
  if (
    normalized.length !== expectedLength ||
    !normalized.startsWith(`0x${ANCHOR_CALLDATA_MAGIC}`)
  ) {
    return null;
  }
  const merkleRoot = normalized.slice(2 + ANCHOR_CALLDATA_MAGIC.length);
  return SHA256_PATTERN.test(merkleRoot)
    ? { protocol: "SITESEALED_ETHEREUM_CALLDATA_V1", merkleRoot }
    : null;
}

export function resolveEthereumConfig(environment = process.env) {
  const mode = String(environment.ETHEREUM_ANCHOR_MODE ?? "disabled")
    .trim()
    .toLowerCase();
  if (mode === "disabled") return null;
  if (mode !== "mainnet") {
    throw new Error('ETHEREUM_ANCHOR_MODE must be either "disabled" or "mainnet".');
  }

  const rpcUrlValue = String(environment.ETHEREUM_RPC_URL ?? "").trim();
  const privateKeyValue = String(
    environment.ETHEREUM_ANCHOR_PRIVATE_KEY ?? "",
  ).trim();
  if (!rpcUrlValue || !privateKeyValue) {
    throw new Error(
      "Ethereum mainnet mode requires ETHEREUM_RPC_URL and ETHEREUM_ANCHOR_PRIVATE_KEY.",
    );
  }
  let rpcUrl;
  try {
    rpcUrl = new URL(rpcUrlValue);
  } catch {
    throw new Error("ETHEREUM_RPC_URL must be a valid HTTPS or WSS URL.");
  }
  if (rpcUrl.protocol !== "https:" && rpcUrl.protocol !== "wss:") {
    throw new Error("ETHEREUM_RPC_URL must use HTTPS or WSS.");
  }
  if (!PRIVATE_KEY_PATTERN.test(privateKeyValue)) {
    throw new Error("ETHEREUM_ANCHOR_PRIVATE_KEY must be a 32-byte hexadecimal key.");
  }

  const privateKey = privateKeyValue.startsWith("0x")
    ? privateKeyValue
    : `0x${privateKeyValue}`;
  return {
    mode,
    chainId: ETHEREUM_MAINNET_CHAIN_ID,
    rpcUrl: rpcUrl.toString(),
    privateKey,
    confirmations: positiveInteger(environment.ETHEREUM_CONFIRMATIONS, 12),
    maxFeeGwei: positiveNumber(environment.ETHEREUM_MAX_FEE_GWEI, 60),
    gasLimit: BigInt(positiveInteger(environment.ETHEREUM_GAS_LIMIT, 30_000)),
  };
}

export function createDisabledEthereumRail() {
  return {
    mode: "disabled",
    configured: false,
    chainId: ETHEREUM_MAINNET_CHAIN_ID,
    network: "Ethereum mainnet",
    async healthCheck() {
      return {
        mode: "disabled",
        status: "not_configured",
        network: "Ethereum mainnet",
        chainId: ETHEREUM_MAINNET_CHAIN_ID,
        writesEnabled: false,
      };
    },
    async close() {},
  };
}

export function createEthereumAnchorClient(
  config,
  { provider, wallet } = {},
) {
  if (!config || config.mode !== "mainnet" || config.chainId !== 1) {
    throw new Error("A valid Ethereum mainnet configuration is required.");
  }
  const activeProvider =
    provider ??
    (config.rpcUrl.startsWith("wss:")
      ? new WebSocketProvider(config.rpcUrl, config.chainId, { staticNetwork: true })
      : new JsonRpcProvider(config.rpcUrl, config.chainId, { staticNetwork: true }));
  const activeWallet = wallet ?? new Wallet(config.privateKey);

  async function assertMainnet() {
    const network = await activeProvider.getNetwork();
    if (Number(network.chainId) !== ETHEREUM_MAINNET_CHAIN_ID) {
      throw new Error(
        `Ethereum RPC returned chain ${network.chainId}; SiteSealed requires mainnet chain 1.`,
      );
    }
  }

  return {
    mode: "ethereum",
    configured: true,
    chainId: ETHEREUM_MAINNET_CHAIN_ID,
    network: "Ethereum mainnet",
    address: activeWallet.address,

    async prepareSignedAnchor({ merkleRoot }) {
      await assertMainnet();
      const [feeData, nonce] = await Promise.all([
        activeProvider.getFeeData(),
        activeProvider.getTransactionCount(activeWallet.address, "pending"),
      ]);
      if (feeData.maxFeePerGas === null || feeData.maxPriorityFeePerGas === null) {
        throw new Error("Ethereum RPC did not return EIP-1559 fee data.");
      }
      const feeCap = parseUnits(String(config.maxFeeGwei), "gwei");
      if (feeData.maxFeePerGas > feeCap) {
        throw new Error(
          `Ethereum max fee ${formatUnits(feeData.maxFeePerGas, "gwei")} gwei exceeds the configured ${config.maxFeeGwei} gwei cap.`,
        );
      }
      const data = encodeAnchorCalldata(merkleRoot);
      const transaction = {
        type: 2,
        chainId: config.chainId,
        nonce,
        to: activeWallet.address,
        value: 0n,
        data,
        gasLimit: config.gasLimit,
        maxFeePerGas: feeData.maxFeePerGas,
        maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
      };
      const signedTransaction = await activeWallet.signTransaction(transaction);
      return {
        transactionHash: keccak256(getBytes(signedTransaction)),
        signedTransaction,
        transactionInput: data,
        anchorAddress: activeWallet.address,
        nonce,
        maxFeePerGas: feeData.maxFeePerGas.toString(),
        maxPriorityFeePerGas: feeData.maxPriorityFeePerGas.toString(),
        gasLimit: config.gasLimit.toString(),
      };
    },

    async broadcastSignedAnchor(signedTransaction, expectedHash) {
      let broadcast;
      try {
        broadcast = await activeProvider.broadcastTransaction(signedTransaction);
      } catch (error) {
        const message = String(error?.shortMessage ?? error?.message ?? "").toLowerCase();
        if (expectedHash && message.includes("nonce too low")) {
          const known = await activeProvider.getTransaction(expectedHash);
          if (known) return expectedHash;
        }
        if (
          expectedHash &&
          (message.includes("already known") || message.includes("known transaction"))
        ) {
          return expectedHash;
        }
        throw error;
      }
      if (
        expectedHash &&
        String(broadcast.hash).toLowerCase() !== String(expectedHash).toLowerCase()
      ) {
        throw new Error("Ethereum RPC returned a different transaction hash.");
      }
      return broadcast.hash;
    },

    async inspectAnchor(batch) {
      await assertMainnet();
      const transactionHash = String(batch.transactionHash ?? "").trim();
      if (!/^0x[a-f0-9]{64}$/i.test(transactionHash)) {
        throw new Error("The anchor batch has no valid Ethereum transaction hash.");
      }
      const transaction = await activeProvider.getTransaction(transactionHash);
      if (!transaction) {
        return { state: "SUBMITTED", confirmations: 0 };
      }
      const expectedData = encodeAnchorCalldata(batch.merkleRoot);
      if (
        String(transaction.data).toLowerCase() !== expectedData.toLowerCase() ||
        String(transaction.from).toLowerCase() !==
          String(batch.anchorAddress).toLowerCase() ||
        String(transaction.to).toLowerCase() !==
          String(batch.anchorAddress).toLowerCase()
      ) {
        return {
          state: "INVALID_ON_CHAIN",
          confirmations: 0,
          verificationStatus: "TRANSACTION_BINDING_MISMATCH",
        };
      }
      const receipt = await activeProvider.getTransactionReceipt(transactionHash);
      if (!receipt) return { state: "SUBMITTED", confirmations: 0 };
      if (Number(receipt.status) !== 1) {
        return {
          state: "FAILED_ON_CHAIN",
          confirmations: 0,
          blockNumber: receipt.blockNumber,
          blockHash: receipt.blockHash,
        };
      }

      const [headNumber, finalizedBlock, anchorBlock] = await Promise.all([
        activeProvider.getBlockNumber(),
        activeProvider.getBlock("finalized").catch(() => null),
        activeProvider.getBlock(receipt.blockNumber),
      ]);
      const confirmations = Math.max(0, headNumber - receipt.blockNumber + 1);
      const finalized =
        finalizedBlock && receipt.blockNumber <= Number(finalizedBlock.number);
      return {
        state: finalized
          ? "FINALIZED"
          : confirmations >= config.confirmations
            ? "CONFIRMED"
            : "SUBMITTED",
        confirmations,
        requiredConfirmations: config.confirmations,
        blockNumber: receipt.blockNumber,
        blockHash: receipt.blockHash,
        anchoredAt:
          anchorBlock?.timestamp === undefined
            ? null
            : new Date(Number(anchorBlock.timestamp) * 1000).toISOString(),
        finalizedAt: finalized ? new Date().toISOString() : null,
        verificationStatus: "TRANSACTION_INPUT_AND_SENDER_MATCH",
      };
    },

    async healthCheck() {
      await assertMainnet();
      return {
        mode: "ethereum",
        status: "connected",
        network: "Ethereum mainnet",
        chainId: ETHEREUM_MAINNET_CHAIN_ID,
        writesEnabled: true,
        anchorAddress: activeWallet.address,
        calldataProtocol: "SITESEALED_ETHEREUM_CALLDATA_V1",
      };
    },

    async close() {
      await activeProvider.destroy?.();
    },
  };
}

export function createEthereumAnchorClientFromEnv(
  environment = process.env,
  options = {},
) {
  const config = resolveEthereumConfig(environment);
  return config
    ? createEthereumAnchorClient(config, options)
    : createDisabledEthereumRail();
}
