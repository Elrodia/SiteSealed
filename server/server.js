import "./load-env.js";
import compression from "compression";
import express from "express";
import helmet from "helmet";
import { createHash, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
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
  createDisabledTimestampService,
  createEvidencyTimestampServiceFromEnv,
} from "./evidency.js";
import {
  createDisabledEthereumRail,
  createEthereumAnchorClientFromEnv,
} from "./ethereum.js";
import {
  ApiError,
  MAX_ENCRYPTED_ORIGINAL_BYTES,
  externalProofStatus,
  isValidRecordId,
  normalizeRecordId,
  scopeForRecord,
  validateSealRequest,
} from "./records.js";
import { renderReceiptPdf } from "./report.js";
import { createMemoryRecordStore } from "./specimen.js";
import {
  createMemoryObjectStore,
  createS3ObjectStoreFromEnv,
  validateEncryptedUpload,
} from "./storage.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const clientDist = path.resolve(__dirname, "../client/dist");
const indexFile = path.join(clientDist, "index.html");

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function safeBaseUrl(request) {
  const configured = String(process.env.PUBLIC_BASE_URL ?? "").trim();
  if (configured) {
    try {
      const url = new URL(configured);
      if (url.protocol === "https:" || url.protocol === "http:") {
        return url.origin;
      }
    } catch {
      // Fall through to the request origin when local configuration is invalid.
    }
  }
  const host = request.get("host") || "localhost";
  return `${request.protocol}://${host}`;
}

function linksFor(request, recordId) {
  const encoded = encodeURIComponent(recordId);
  const baseUrl = safeBaseUrl(request);
  return {
    verify: `${baseUrl}/verify/${encoded}`,
    publicBundle: `${baseUrl}/api/records/${encoded}/bundle`,
    receiptPdf: `${baseUrl}/api/records/${encoded}/report.pdf`,
    timestampToken: `${baseUrl}/api/records/${encoded}/timestamp.tsr`,
    encryptedOriginal: `${baseUrl}/api/records/${encoded}/encrypted-original`,
  };
}

function recoveryTokenDigest(value) {
  const encoded = String(value ?? "").trim();
  if (
    encoded.length === 0 ||
    encoded.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)
  ) {
    throw new ApiError(
      400,
      "INVALID_RECOVERY_TOKEN",
      "recoveryToken must be canonical base64 containing 32 random bytes.",
    );
  }
  const token = Buffer.from(encoded, "base64");
  if (token.length !== 32 || token.toString("base64") !== encoded) {
    throw new ApiError(
      400,
      "INVALID_RECOVERY_TOKEN",
      "recoveryToken must be canonical base64 containing 32 random bytes.",
    );
  }
  return createHash("sha256").update(token).digest("hex");
}

function sameDigest(left, right) {
  const leftBytes = Buffer.from(String(left), "hex");
  const rightBytes = Buffer.from(String(right), "hex");
  return (
    leftBytes.length === 32 &&
    rightBytes.length === 32 &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

export function createSealRateLimiter({
  coordinator,
  scope = "seal",
  limit = 20,
  windowMs = 60 * 60 * 1000,
} = {}) {
  const activeCoordinator = coordinator ?? createMemoryCoordinator();

  return async (request, response, next) => {
    try {
      const identity =
        request.ip || request.socket.remoteAddress || "unknown-client";
      const result = await activeCoordinator.consumeRateLimit({
        scope,
        identity,
        limit,
        windowMs,
      });
      const resetSeconds = Math.max(1, Math.ceil(result.resetInMs / 1000));
      response.set("RateLimit-Limit", String(result.limit));
      response.set("RateLimit-Remaining", String(result.remaining));
      response.set("RateLimit-Reset", String(resetSeconds));

      if (result.allowed) return next();
      response.set("Retry-After", String(resetSeconds));
      return response.status(429).json({
        ok: false,
        code: "SEAL_RATE_LIMITED",
        message: "The anonymous sealing limit has been reached. Try again after the reset time.",
      });
    } catch (error) {
      console.error(`Distributed rate limiter failed: ${error.message}`);
      return next(
        new ApiError(
          503,
          "COORDINATION_UNAVAILABLE",
          "The distributed sealing guard is temporarily unavailable.",
        ),
      );
    }
  };
}

function auditBoundary(record, audit) {
  if (record.specimen) {
    return {
      state: "NOT_APPLICABLE_SPECIMEN",
      role: "APPLICATION_AUDIT_ONLY",
      independentlyAnchored: false,
    };
  }
  return (
    audit ?? {
      state: "NOT_RECORDED_LEGACY",
      role: "APPLICATION_AUDIT_ONLY",
      independentlyAnchored: false,
      message: "This receipt predates the PostgreSQL operational audit.",
    }
  );
}

function verificationPayload(record, audit = null) {
  const proofStatus = externalProofStatus(record);
  return {
    ok: true,
    specimen: Boolean(record.specimen),
    status: record.specimen ? "SPECIMEN_RECORD_FOUND" : proofStatus.state,
    proofsComplete: proofStatus.proofsComplete,
    alphaComplete: proofStatus.alphaComplete,
    sealed: proofStatus.sealed,
    checkedAt: new Date().toISOString(),
    record,
    operationalAudit: auditBoundary(record, audit),
    scope: scopeForRecord(record),
  };
}

function bundleWithAudit(bundle, record, audit) {
  if (record.specimen) {
    return {
      ...bundle,
      operationalAudit: auditBoundary(record, null),
    };
  }
  return {
    ...bundle,
    schemaVersion: "sitesealed.proof-bundle.v1.4-alpha.1",
    bundleVersion: "1.4-alpha.1",
    operationalAudit: auditBoundary(record, audit),
  };
}

function requireRecordId(value) {
  const recordId = normalizeRecordId(value);
  if (!recordId || recordId.length > 64 || !isValidRecordId(recordId)) {
    throw new ApiError(400, "INVALID_RECORD_ID", "Enter a valid SiteSealed record ID.");
  }
  return recordId;
}

export function createApp({
  recordStore = createMemoryRecordStore(),
  objectStore = createMemoryObjectStore(),
  auditStore = createMemoryAuditStore(),
  coordinator = createMemoryCoordinator(),
  timestampService = createDisabledTimestampService(),
  ethereumRail = createDisabledEthereumRail(),
  sealRateLimit = positiveInteger(process.env.SEAL_RATE_LIMIT_PER_HOUR, 20),
} = {}) {
  const app = express();

  const timestampHealth = async () => {
    const local = await timestampService.healthCheck();
    const shared = await coordinator.getRailRuntimeStatus?.("evidency");
    return shared ?? local;
  };

  const findRecord = async (recordId) => {
    try {
      const cached = await coordinator.getCachedRecord(recordId);
      if (cached) return cached;
    } catch (error) {
      console.error(`Redis verification cache read failed: ${error.message}`);
    }
    const record = await recordStore.findById(recordId);
    if (record) {
      await coordinator
        .setCachedRecord(recordId, record)
        .catch((error) =>
          console.error(`Redis verification cache write failed: ${error.message}`),
        );
    }
    return record;
  };

  const findAudit = async (recordId) => {
    try {
      return await auditStore.findByRecordId(recordId);
    } catch (error) {
      console.error(`PostgreSQL audit read failed: ${error.message}`);
      return {
        state: "TEMPORARILY_UNAVAILABLE",
        role: "APPLICATION_AUDIT_ONLY",
        independentlyAnchored: false,
      };
    }
  };

  app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use(
    helmet({
      crossOriginResourcePolicy: { policy: "same-origin" },
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", "data:"],
          fontSrc: ["'self'"],
          connectSrc: ["'self'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          upgradeInsecureRequests: null,
        },
      },
    }),
  );
  app.use(compression());
  app.use(express.json({ limit: "96kb", strict: true }));

  app.use("/api", (_request, response, next) => {
    response.set("Cache-Control", "no-store");
    next();
  });

  app.get("/api/health", async (_request, response) => {
    const [
      database,
      objectStorage,
      auditDatabase,
      coordination,
      qualifiedTimestamp,
      publicChainAnchor,
    ] =
      await Promise.all([
      recordStore.healthCheck(),
      objectStore.healthCheck(),
      auditStore.healthCheck(),
      coordinator.healthCheck(),
      timestampHealth(),
      ethereumRail.healthCheck(),
    ]);
    response.status(200).json({
      ok: true,
      service: "sitesealed",
      version: "1.4.0-alpha.5",
      sealing: {
        workflow: "IMPORTED_FILE_CLIENT_ENCRYPTED_STORAGE_RECEIPT",
        clientEncryptedObjectStorage: true,
        operationalAudit: "POSTGRESQL_APPEND_ONLY_HASH_CHAIN",
        distributedCoordination: true,
        qualifiedTimestamp:
          qualifiedTimestamp.status === "operational"
            ? "EVIDENCY_SANDBOX_OPERATIONAL_TEST_ONLY"
            : [
                  "configured",
                  "dry_run_ready",
                  "dry_run_no_eligible_record",
                ].includes(qualifiedTimestamp.status)
              ? "EVIDENCY_SANDBOX_READY_TEST_ONLY"
              : false,
        publicChainAnchor:
          publicChainAnchor.mode === "ethereum"
            ? "ETHEREUM_MAINNET_ENABLED"
            : false,
        finalSealedStatusEnabled: false,
      },
      database,
      objectStorage,
      auditDatabase,
      coordination,
      qualifiedTimestamp,
      publicChainAnchor,
    });
  });

  app.put(
    "/api/storage/uploads/:submissionId",
    createSealRateLimiter({
      coordinator,
      scope: "encrypted-upload",
      limit: sealRateLimit,
    }),
    express.raw({
      type: "application/octet-stream",
      limit: MAX_ENCRYPTED_ORIGINAL_BYTES,
    }),
    async (request, response) => {
      if (!request.is("application/octet-stream")) {
        throw new ApiError(
          415,
          "UNSUPPORTED_UPLOAD_MEDIA_TYPE",
          "Encrypted originals must use application/octet-stream.",
        );
      }
      const upload = validateEncryptedUpload({
        submissionId: request.params.submissionId,
        headers: request.headers,
        body: request.body,
      });
      const result = await objectStore.putEncryptedOriginal(upload);
      return response.status(result.created ? 201 : 200).json({
        ok: true,
        created: result.created,
        status: result.created
          ? "ENCRYPTED_ORIGINAL_STORED"
          : "ENCRYPTED_ORIGINAL_REUSED",
        encryptedObject: result.descriptor,
        storage: {
          mode: objectStore.mode,
          persistent: Boolean(objectStore.persistent),
          plaintextReceived: false,
        },
      });
    },
  );

  app.post(
    "/api/records",
    createSealRateLimiter({
      coordinator,
      scope: "receipt-create",
      limit: sealRateLimit,
    }),
    async (request, response) => {
      const input = validateSealRequest(request.body);
      let releaseLock;
      try {
        releaseLock = await coordinator.acquireSubmissionLock(
          input.submissionId,
        );
      } catch (error) {
        console.error(`Submission lock acquisition failed: ${error.message}`);
        throw new ApiError(
          503,
          "COORDINATION_UNAVAILABLE",
          "Distributed submission coordination is temporarily unavailable.",
        );
      }
      if (!releaseLock) {
        throw new ApiError(
          409,
          "SUBMISSION_IN_PROGRESS",
          "This submission is already being sealed. Retry shortly with the same submission ID.",
        );
      }

      try {
        await objectStore.assertStored(input.encryptedObject, input);
        const result = await recordStore.create({
          ...input,
          storageProvider:
            objectStore.mode === "s3" ? "S3_PRIVATE_BUCKET" : "MEMORY",
        });
        let auditResult;
        try {
          auditResult = await auditStore.appendReceipt(result.record, {
            submissionId: input.submissionId,
          });
        } catch (error) {
          if (error instanceof ApiError) throw error;
          console.error(`PostgreSQL audit append failed: ${error.message}`);
          throw new ApiError(
            503,
            "AUDIT_UNAVAILABLE",
            "The operational audit could not be recorded. Retry with the same submission ID.",
          );
        }
        await coordinator
          .setCachedRecord(result.record.recordId, result.record)
          .catch((error) =>
            console.error(
              `Redis verification cache write failed: ${error.message}`,
            ),
          );

        const status = result.created ? 201 : 200;
        return response
          .status(status)
          .location(`/api/verify/${encodeURIComponent(result.record.recordId)}`)
          .json({
            ok: true,
            created: result.created,
            status: result.created
              ? "DUAL_RAIL_ALPHA_RECEIPT_CREATED"
              : "IDEMPOTENT_RECEIPT_REUSED",
            record: result.record,
            operationalAudit: auditBoundary(
              result.record,
              auditResult.audit,
            ),
            scope: scopeForRecord(result.record),
            storage: {
              persistent: Boolean(
                recordStore.persistent &&
                  objectStore.persistent &&
                  auditStore.persistent,
              ),
              database: {
                mode: recordStore.mode,
                persistent: Boolean(recordStore.persistent),
              },
              objects: {
                mode: objectStore.mode,
                persistent: Boolean(objectStore.persistent),
                state: result.record.storage.state,
                plaintextReceived: false,
              },
              audit: {
                mode: auditStore.mode,
                persistent: Boolean(auditStore.persistent),
                appendOnly: Boolean(auditStore.appendOnly),
                hashChained: Boolean(auditStore.hashChained),
                independentlyAnchored: false,
              },
            },
            coordination: {
              mode: coordinator.mode,
              distributed: Boolean(coordinator.distributed),
              authoritative: false,
            },
            links: linksFor(request, result.record.recordId),
          });
      } finally {
        await releaseLock().catch((error) =>
          console.error(`Submission lock release failed: ${error.message}`),
        );
      }
    },
  );

  const verifyRecord = async (request, response) => {
    const recordId = requireRecordId(
      request.params.recordId ?? request.body?.recordId,
    );
    const record = await findRecord(recordId);
    if (!record) {
      return response.status(404).json({
        ok: false,
        code: "RECORD_NOT_FOUND",
        message: "No SiteSealed record was found for this identifier.",
      });
    }
    const audit = await findAudit(recordId);
    return response.status(200).json(verificationPayload(record, audit));
  };

  app.get("/api/verify/:recordId", verifyRecord);
  app.post("/api/verify", verifyRecord);

  app.get("/api/records/:recordId/bundle", async (request, response) => {
    const recordId = requireRecordId(request.params.recordId);
    const [bundle, record] = await Promise.all([
      recordStore.getBundleById(recordId),
      findRecord(recordId),
    ]);
    if (!bundle || !record) {
      return response.status(404).json({
        ok: false,
        code: "RECORD_NOT_FOUND",
        message: "No SiteSealed record was found for this identifier.",
      });
    }
    const audit = await findAudit(recordId);
    const publicBundle = bundleWithAudit(bundle, record, audit);
    response.set(
      "Content-Disposition",
      `attachment; filename="SiteSealed_${recordId}_proof-bundle.json"`,
    );
    response.type("application/json");
    return response.send(`${JSON.stringify(publicBundle, null, 2)}\n`);
  });

  app.get("/api/records/:recordId/report.pdf", async (request, response) => {
    const recordId = requireRecordId(request.params.recordId);
    const record = await findRecord(recordId);
    if (!record) {
      return response.status(404).json({
        ok: false,
        code: "RECORD_NOT_FOUND",
        message: "No SiteSealed record was found for this identifier.",
      });
    }
    if (record.specimen) {
      return response.redirect(302, "/documents/SiteSealed_EvidenceReport_SPECIMEN.pdf");
    }
    const pdf = await renderReceiptPdf(record, { baseUrl: safeBaseUrl(request) });
    response.set(
      "Content-Disposition",
      `attachment; filename="SiteSealed_${recordId}_alpha-receipt.pdf"`,
    );
    response.type("application/pdf");
    return response.send(pdf);
  });

  app.get("/api/records/:recordId/timestamp.tsr", async (request, response) => {
    const recordId = requireRecordId(request.params.recordId);
    const record = await findRecord(recordId);
    if (!record || !record.qualifiedRail?.token) {
      return response.status(404).json({
        ok: false,
        code: "TIMESTAMP_TOKEN_NOT_FOUND",
        message: "No exportable RFC 3161 timestamp token is attached to this record.",
      });
    }
    const token = Buffer.from(record.qualifiedRail.token, "base64");
    if (token.length < 16 || token.toString("base64") !== record.qualifiedRail.token) {
      throw new ApiError(
        500,
        "TIMESTAMP_TOKEN_CORRUPT",
        "The stored timestamp token failed its Base64 integrity check.",
      );
    }
    if (createHash("sha256").update(token).digest("hex") !== record.qualifiedRail.tokenSha256) {
      throw new ApiError(
        500,
        "TIMESTAMP_TOKEN_CORRUPT",
        "The stored timestamp token failed its SHA-256 integrity check.",
      );
    }
    response.set({
      "Content-Disposition": `attachment; filename="SiteSealed_${recordId}_Evidency_SANDBOX.tsr"`,
      "X-SiteSealed-Environment": record.qualifiedRail.environment,
      "X-SiteSealed-Legal-Use": String(Boolean(record.qualifiedRail.legalUse)),
      "X-SiteSealed-Token-Sha256": record.qualifiedRail.tokenSha256,
    });
    response.type("application/timestamp-reply");
    return response.send(token);
  });

  app.post(
    "/api/records/:recordId/encrypted-original",
    async (request, response) => {
      const recordId = requireRecordId(request.params.recordId);
      if (
        !request.body ||
        typeof request.body !== "object" ||
        Array.isArray(request.body) ||
        Object.keys(request.body).some((key) => key !== "recoveryToken")
      ) {
        throw new ApiError(
          400,
          "INVALID_RECOVERY_REQUEST",
          "Provide only the recoveryToken from the private recovery kit.",
        );
      }
      const reference = await recordStore.getEncryptedObjectReferenceById(recordId);
      if (!reference) {
        return response.status(404).json({
          ok: false,
          code: "ENCRYPTED_ORIGINAL_NOT_FOUND",
          message: "No encrypted original is attached to this record.",
        });
      }
      const suppliedDigest = recoveryTokenDigest(request.body.recoveryToken);
      if (!sameDigest(suppliedDigest, reference.recoveryTokenSha256)) {
        return response.status(403).json({
          ok: false,
          code: "RECOVERY_TOKEN_REJECTED",
          message: "The private recovery token is not valid for this record.",
        });
      }

      const encryptedOriginal = await objectStore.getEncryptedOriginal(reference);
      response.set({
        "Cache-Control": "private, no-store",
        "Content-Disposition": `attachment; filename="SiteSealed_${recordId}_encrypted-original.ssenc"`,
        "X-SiteSealed-Encryption": "AES-256-GCM",
        "X-SiteSealed-Cipher-Sha256": reference.ciphertextSha256,
        "X-SiteSealed-Cipher-Iv": reference.iv,
      });
      response.type("application/vnd.sitesealed.encrypted-original");
      return response.send(encryptedOriginal);
    },
  );

  app.use("/api", (_request, response) => {
    response.status(404).json({
      ok: false,
      code: "API_ROUTE_NOT_FOUND",
      message: "API route not found.",
    });
  });

  if (existsSync(indexFile)) {
    app.use(
      express.static(clientDist, {
        index: false,
        maxAge: "7d",
        setHeaders(response, filePath) {
          if (
            filePath.endsWith(".html") ||
            filePath.endsWith("favicon.svg") ||
            filePath.endsWith("icon-192.svg") ||
            filePath.endsWith("icon-512.svg") ||
            filePath.endsWith("site.webmanifest")
          ) {
            response.setHeader("Cache-Control", "no-cache");
          }
        },
      }),
    );

    app.use((request, response, next) => {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return next();
      }
      response.set("Cache-Control", "no-cache");
      return response.sendFile(indexFile);
    });
  } else {
    app.get("/", (_request, response) => {
      response.status(503).json({
        ok: false,
        message: "Client build not found. Run npm run build before npm start.",
      });
    });
  }

  app.use((error, _request, response, _next) => {
    if (error instanceof ApiError) {
      return response.status(error.status).json({
        ok: false,
        code: error.code,
        message: error.message,
      });
    }
    if (error?.type === "entity.too.large") {
      return response.status(413).json({
        ok: false,
        code: "REQUEST_TOO_LARGE",
        message: "The request exceeds the v1.4 encrypted upload limit.",
      });
    }
    if (error instanceof SyntaxError && error.status === 400) {
      return response.status(400).json({
        ok: false,
        code: "INVALID_JSON",
        message: "Request body must contain valid JSON.",
      });
    }
    console.error("Unhandled request error", error);
    return response.status(500).json({
      ok: false,
      code: "INTERNAL_ERROR",
      message: "An unexpected error occurred.",
    });
  });

  return app;
}

function parsePort(value) {
  const port = Number.parseInt(String(value ?? "3000"), 10);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : 3000;
}

export async function startServer() {
  const port = parsePort(process.env.PORT);
  const host = process.env.HOST || "0.0.0.0";
  let recordStore;
  let objectStore;
  let auditStore;
  let coordinator;
  let timestampService;
  let ethereumRail;
  try {
    recordStore =
      (await createMysqlRecordStoreFromEnv(process.env)) ??
      createMemoryRecordStore();
    objectStore =
      (await createS3ObjectStoreFromEnv(process.env)) ??
      createMemoryObjectStore();
    auditStore =
      (await createPostgresAuditStoreFromEnv(process.env)) ??
      createMemoryAuditStore();
    coordinator =
      (await createRedisCoordinatorFromEnv(process.env)) ??
      createMemoryCoordinator();
    timestampService = createEvidencyTimestampServiceFromEnv(process.env);
    ethereumRail = createEthereumAnchorClientFromEnv(process.env);
  } catch (error) {
    await Promise.all([
      recordStore?.close().catch(() => {}),
      objectStore?.close().catch(() => {}),
      auditStore?.close().catch(() => {}),
      coordinator?.close().catch(() => {}),
      timestampService?.close().catch(() => {}),
      ethereumRail?.close().catch(() => {}),
    ]);
    throw error;
  }
  const app = createApp({
    recordStore,
    objectStore,
    auditStore,
    coordinator,
    timestampService,
    ethereumRail,
  });
  const server = app.listen(port, host, () => {
    console.log(
      `SiteSealed v1.4-alpha.5 listening on ${host}:${port} with ${recordStore.mode} records, ${objectStore.mode} objects, ${auditStore.mode} audit, ${coordinator.mode} coordination, ${timestampService.mode} time and ${ethereumRail.mode} anchor rails.`,
    );
  });

  let shuttingDown = false;
  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`${signal} received; closing HTTP server.`);
    const timeout = setTimeout(() => process.exit(1), 10_000);
    timeout.unref();
    server.close(async () => {
      try {
        await Promise.all([
          recordStore.close(),
          objectStore.close(),
          auditStore.close(),
          coordinator.close(),
          timestampService.close(),
          ethereumRail.close(),
        ]);
        clearTimeout(timeout);
        process.exit(0);
      } catch (error) {
        console.error(`Storage shutdown failed: ${error.message}`);
        process.exit(1);
      }
    });
  };

  process.once("SIGTERM", () => shutdown("SIGTERM"));
  process.once("SIGINT", () => shutdown("SIGINT"));
  return {
    server,
    recordStore,
    objectStore,
    auditStore,
    coordinator,
    timestampService,
    ethereumRail,
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  startServer().catch((error) => {
    console.error(`SiteSealed failed to start: ${error.message}`);
    process.exitCode = 1;
  });
}
