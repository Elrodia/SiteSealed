import {
  JsonRpcProvider,
  Transaction,
  WebSocketProvider,
  Wallet,
  formatEther,
  formatUnits,
  getAddress,
  parseEther,
  parseUnits,
} from "ethers";

export const ETHEREUM_MAINNET_CHAIN_ID = 1;
export const ANCHOR_CALLDATA_MAGIC = "53534c4401";
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const PRIVATE_KEY_PATTERN = /^(?:0x)?[a-f0-9]{64}$/i;

function strictPositiveInteger(value, fallback, variableName) {
  if (value === undefined || value === null || String(value).trim() === "") {
    return fallback;
  }
  const normalized = String(value).trim();
  if (!/^[0-9]+$/.test(normalized)) {
    throw new Error(`${variableName} must be a positive integer.`);
  }
  const parsed = Number(normalized);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${variableName} must be a positive integer.`);
  }
  return parsed;
}

function strictPositiveDecimal(value, fallback, variableName) {
  const normalized =
    value === undefined || value === null || String(value).trim() === ""
      ? String(fallback)
      : String(value).trim();
  if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(normalized)) {
    throw new Error(`${variableName} must be a positive decimal value.`);
  }
  const parsed = Number(normalized);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${variableName} must be a positive decimal value.`);
  }
  return { value: parsed, text: normalized };
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
  const expectedAddressValue = String(
    environment.ETHEREUM_EXPECTED_ANCHOR_ADDRESS ?? "",
  ).trim();
  if (!rpcUrlValue || !privateKeyValue) {
    throw new Error(
      "Ethereum mainnet mode requires ETHEREUM_RPC_URL and ETHEREUM_ANCHOR_PRIVATE_KEY.",
    );
  }
  if (!expectedAddressValue) {
    throw new Error(
      "Ethereum mainnet mode requires ETHEREUM_EXPECTED_ANCHOR_ADDRESS.",
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
  if (rpcUrl.username || rpcUrl.password) {
    throw new Error(
      "ETHEREUM_RPC_URL must not contain HTTP basic-auth credentials.",
    );
  }
  if (!PRIVATE_KEY_PATTERN.test(privateKeyValue)) {
    throw new Error("ETHEREUM_ANCHOR_PRIVATE_KEY must be a 32-byte hexadecimal key.");
  }

  let expectedAnchorAddress;
  try {
    expectedAnchorAddress = getAddress(expectedAddressValue);
  } catch {
    throw new Error("ETHEREUM_EXPECTED_ANCHOR_ADDRESS must be a valid Ethereum address.");
  }

  const maxFee = strictPositiveDecimal(
    environment.ETHEREUM_MAX_FEE_GWEI,
    5,
    "ETHEREUM_MAX_FEE_GWEI",
  );
  const maxTransactionFee = strictPositiveDecimal(
    environment.ETHEREUM_MAX_TX_FEE_ETH,
    "0.00015",
    "ETHEREUM_MAX_TX_FEE_ETH",
  );
  const privateKey = privateKeyValue.startsWith("0x")
    ? privateKeyValue
    : `0x${privateKeyValue}`;

  return {
    mode,
    chainId: ETHEREUM_MAINNET_CHAIN_ID,
    rpcUrl: rpcUrl.toString(),
    privateKey,
    expectedAnchorAddress,
    confirmations: strictPositiveInteger(
      environment.ETHEREUM_CONFIRMATIONS,
      12,
      "ETHEREUM_CONFIRMATIONS",
    ),
    maxFeeGwei: maxFee.value,
    maxFeePerGas: parseUnits(maxFee.text, "gwei"),
    maxTransactionFeeEth: maxTransactionFee.text,
    maxTransactionFeeWei: parseEther(maxTransactionFee.text),
    gasLimit: BigInt(
      strictPositiveInteger(
        environment.ETHEREUM_GAS_LIMIT,
        30_000,
        "ETHEREUM_GAS_LIMIT",
      ),
    ),
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
    async probeRpc() {},
    async close() {},
  };
}

export function createEthereumAnchorClient(config, { provider, wallet } = {}) {
  if (!config || config.mode !== "mainnet" || config.chainId !== 1) {
    throw new Error("A valid Ethereum mainnet configuration is required.");
  }
  const activeProvider =
    provider ??
    (config.rpcUrl.startsWith("wss:")
      ? new WebSocketProvider(config.rpcUrl, config.chainId, { staticNetwork: true })
      : new JsonRpcProvider(config.rpcUrl, config.chainId, { staticNetwork: true }));
  const activeWallet = wallet ?? new Wallet(config.privateKey);
  const expectedAnchorAddress = getAddress(config.expectedAnchorAddress);
  const walletAddress = getAddress(activeWallet.address);
  if (walletAddress !== expectedAnchorAddress) {
    throw new Error(
      `Ethereum signing key resolves to ${walletAddress}, not ETHEREUM_EXPECTED_ANCHOR_ADDRESS ${expectedAnchorAddress}.`,
    );
  }

  const maxFeePerGas =
    config.maxFeePerGas ?? parseUnits(String(config.maxFeeGwei), "gwei");
  const maxTransactionFeeWei =
    config.maxTransactionFeeWei ?? parseEther("0.00015");

  async function assertMainnet() {
    const network = await activeProvider.getNetwork();
    if (Number(network.chainId) !== ETHEREUM_MAINNET_CHAIN_ID) {
      throw new Error(
        `Ethereum RPC returned chain ${network.chainId}; SiteSealed requires mainnet chain 1.`,
      );
    }
  }

  async function assessAnchor({ merkleRoot }) {
    await assertMainnet();
    const data = encodeAnchorCalldata(merkleRoot);
    const [feeData, estimatedGas, walletBalance] = await Promise.all([
      activeProvider.getFeeData(),
      activeProvider.estimateGas({
        from: walletAddress,
        to: walletAddress,
        value: 0n,
        data,
      }),
      activeProvider.getBalance(walletAddress, "pending"),
    ]);
    if (feeData.maxFeePerGas === null || feeData.maxPriorityFeePerGas === null) {
      throw new Error("Ethereum RPC did not return EIP-1559 fee data.");
    }
    if (feeData.maxPriorityFeePerGas > feeData.maxFeePerGas) {
      throw new Error("Ethereum RPC returned an invalid EIP-1559 priority fee.");
    }
    if (feeData.maxFeePerGas > maxFeePerGas) {
      throw new Error(
        `Ethereum max fee ${formatUnits(feeData.maxFeePerGas, "gwei")} gwei exceeds the configured ${config.maxFeeGwei} gwei cap.`,
      );
    }
    if (estimatedGas > config.gasLimit) {
      throw new Error(
        `Ethereum estimated gas ${estimatedGas} exceeds the configured gas limit ${config.gasLimit}.`,
      );
    }
    const maximumAuthorizedFee = config.gasLimit * feeData.maxFeePerGas;
    if (maximumAuthorizedFee > maxTransactionFeeWei) {
      throw new Error(
        `Ethereum maximum authorized fee ${formatEther(maximumAuthorizedFee)} ETH exceeds the configured ${formatEther(maxTransactionFeeWei)} ETH transaction cap.`,
      );
    }
    if (walletBalance < maximumAuthorizedFee) {
      throw new Error(
        `Ethereum anchor wallet balance is insufficient for the maximum authorized transaction fee (${formatEther(maximumAuthorizedFee)} ETH).`,
      );
    }
    return {
      data,
      feeData,
      estimatedGas,
      walletBalance,
      maximumAuthorizedFee,
    };
  }

  function verifyLocallySignedTransaction(signedTransaction, expected) {
    let parsed;
    try {
      parsed = Transaction.from(signedTransaction);
    } catch {
      throw new Error("The locally signed Ethereum transaction could not be decoded.");
    }
    const matches =
      parsed.type === 2 &&
      Number(parsed.chainId) === ETHEREUM_MAINNET_CHAIN_ID &&
      parsed.nonce === expected.nonce &&
      getAddress(parsed.from) === walletAddress &&
      getAddress(parsed.to) === walletAddress &&
      parsed.value === 0n &&
      String(parsed.data).toLowerCase() === expected.data.toLowerCase() &&
      parsed.gasLimit === config.gasLimit &&
      parsed.maxFeePerGas === expected.maxFeePerGas &&
      parsed.maxPriorityFeePerGas === expected.maxPriorityFeePerGas;
    if (!matches || !parsed.hash) {
      throw new Error(
        "The locally signed Ethereum transaction does not match the authorized mainnet anchor.",
      );
    }
    return parsed.hash;
  }

  return {
    mode: "ethereum",
    configured: true,
    chainId: ETHEREUM_MAINNET_CHAIN_ID,
    network: "Ethereum mainnet",
    address: walletAddress,
    expectedAnchorAddress,
    maxFeeGwei: config.maxFeeGwei,
    maxTransactionFeeEth:
      config.maxTransactionFeeEth ?? formatEther(maxTransactionFeeWei),
    gasLimit: config.gasLimit.toString(),

    async previewAnchor({ merkleRoot }) {
      const assessment = await assessAnchor({ merkleRoot });
      return {
        transactionInput: assessment.data,
        anchorAddress: walletAddress,
        estimatedGas: assessment.estimatedGas.toString(),
        gasLimit: config.gasLimit.toString(),
        maxFeePerGas: assessment.feeData.maxFeePerGas.toString(),
        maxPriorityFeePerGas:
          assessment.feeData.maxPriorityFeePerGas.toString(),
        maximumAuthorizedFeeWei: assessment.maximumAuthorizedFee.toString(),
        maximumAuthorizedFeeEth: formatEther(assessment.maximumAuthorizedFee),
        walletBalanceWei: assessment.walletBalance.toString(),
        walletBalanceEth: formatEther(assessment.walletBalance),
      };
    },

    async prepareSignedAnchor({ merkleRoot }) {
      const assessment = await assessAnchor({ merkleRoot });
      const nonce = await activeProvider.getTransactionCount(
        walletAddress,
        "pending",
      );
      const transaction = {
        type: 2,
        chainId: config.chainId,
        nonce,
        to: walletAddress,
        value: 0n,
        data: assessment.data,
        gasLimit: config.gasLimit,
        maxFeePerGas: assessment.feeData.maxFeePerGas,
        maxPriorityFeePerGas: assessment.feeData.maxPriorityFeePerGas,
      };
      const signedTransaction = await activeWallet.signTransaction(transaction);
      const transactionHash = verifyLocallySignedTransaction(
        signedTransaction,
        transaction,
      );
      return {
        transactionHash,
        signedTransaction,
        transactionInput: assessment.data,
        anchorAddress: walletAddress,
        nonce,
        maxFeePerGas: assessment.feeData.maxFeePerGas.toString(),
        maxPriorityFeePerGas:
          assessment.feeData.maxPriorityFeePerGas.toString(),
        gasLimit: config.gasLimit.toString(),
        estimatedGas: assessment.estimatedGas.toString(),
        maximumAuthorizedFeeWei: assessment.maximumAuthorizedFee.toString(),
      };
    },

    async broadcastSignedAnchor(batch) {
      await assertMainnet();
      if (
        !batch ||
        getAddress(batch.anchorAddress) !== expectedAnchorAddress ||
        String(batch.merkleRoot ?? "").toLowerCase() === ""
      ) {
        throw new Error("The persisted Ethereum anchor is incomplete or uses an unexpected address.");
      }
      const expectedTransaction = {
        nonce: Number(batch.nonce),
        data: encodeAnchorCalldata(batch.merkleRoot),
        maxFeePerGas: BigInt(batch.maxFeePerGas),
        maxPriorityFeePerGas: BigInt(batch.maxPriorityFeePerGas),
      };
      if (BigInt(batch.gasLimit) !== config.gasLimit) {
        throw new Error(
          "The persisted Ethereum gas limit does not match the configured authorization.",
        );
      }
      const locallyVerifiedHash = verifyLocallySignedTransaction(
        batch.signedTransaction,
        expectedTransaction,
      );
      if (
        locallyVerifiedHash.toLowerCase() !==
        String(batch.transactionHash ?? "").toLowerCase()
      ) {
        throw new Error(
          "The persisted Ethereum transaction hash does not match the locally decoded signed transaction.",
        );
      }
      if (
        expectedTransaction.maxFeePerGas > maxFeePerGas ||
        expectedTransaction.maxPriorityFeePerGas >
          expectedTransaction.maxFeePerGas ||
        config.gasLimit * expectedTransaction.maxFeePerGas >
          maxTransactionFeeWei
      ) {
        throw new Error(
          "The persisted Ethereum transaction exceeds the configured fee authorization.",
        );
      }

      const expectedHash = batch.transactionHash;
      let broadcast;
      try {
        broadcast = await activeProvider.broadcastTransaction(
          batch.signedTransaction,
        );
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
      if (getAddress(batch.anchorAddress) !== expectedAnchorAddress) {
        throw new Error("The stored anchor address does not match the expected wallet.");
      }
      // A pending mempool transaction is not yet an on-chain object. Some RPC
      // providers expose partial or transient transaction fields before the
      // receipt exists, so classifying its binding at that point can create a
      // false terminal INVALID_ON_CHAIN result. Wait for a mined receipt first;
      // the exact signed transaction was already verified locally before send.
      const receipt = await activeProvider.getTransactionReceipt(transactionHash);
      if (!receipt) {
        return {
          state: "SUBMITTED",
          confirmations: 0,
          onChainBindingVerified: false,
          finalityVerified: false,
          verificationStatus: "TRANSACTION_PENDING_RECEIPT",
        };
      }
      const transaction = await activeProvider.getTransaction(transactionHash);
      if (!transaction) {
        return {
          state: "SUBMITTED",
          confirmations: 0,
          blockNumber: receipt.blockNumber,
          blockHash: receipt.blockHash,
          onChainBindingVerified: false,
          finalityVerified: false,
          verificationStatus: "MINED_TRANSACTION_PENDING_RPC_VISIBILITY",
        };
      }
      const expectedData = encodeAnchorCalldata(batch.merkleRoot);
      if (
        Number(transaction.chainId ?? ETHEREUM_MAINNET_CHAIN_ID) !==
          ETHEREUM_MAINNET_CHAIN_ID ||
        String(transaction.data).toLowerCase() !== expectedData.toLowerCase() ||
        String(transaction.from).toLowerCase() !== expectedAnchorAddress.toLowerCase() ||
        String(transaction.to).toLowerCase() !== expectedAnchorAddress.toLowerCase()
      ) {
        return {
          state: "INVALID_ON_CHAIN",
          confirmations: 0,
          onChainBindingVerified: false,
          finalityVerified: false,
          verificationStatus: "TRANSACTION_BINDING_MISMATCH",
        };
      }
      if (Number(receipt.status) !== 1) {
        return {
          state: "FAILED_ON_CHAIN",
          confirmations: 0,
          blockNumber: receipt.blockNumber,
          blockHash: receipt.blockHash,
          onChainBindingVerified: true,
          finalityVerified: false,
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
        onChainBindingVerified: true,
        finalityVerified: Boolean(finalized),
        verificationStatus: "TRANSACTION_INPUT_AND_SENDER_MATCH",
      };
    },

    async healthCheck() {
      await assertMainnet();
      return {
        mode: "ethereum",
        status: "configured",
        network: "Ethereum mainnet",
        chainId: ETHEREUM_MAINNET_CHAIN_ID,
        configured: true,
        writesEnabled: true,
        anchorAddress: walletAddress,
        expectedAnchorAddress,
        calldataProtocol: "SITESEALED_ETHEREUM_CALLDATA_V1",
      };
    },

    async probeRpc() {
      // staticNetwork short-circuits getNetwork(), so probe the wire directly.
      // This turns silent credential failures into an explicit, early error
      // at worker startup — without burdening the server /api/health path.
      await activeProvider.getBlockNumber();
    },

    async close() {
      const socket = activeProvider.websocket;
      // A ws instance torn down mid-handshake emits an async 'error' event
      // that no promise chain can catch. Attach the sink BEFORE destroy().
      socket?.on?.("error", () => {});
      try {
        await activeProvider.destroy?.();
      } catch {
        // Teardown must never fail an otherwise-verified run.
      }
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
