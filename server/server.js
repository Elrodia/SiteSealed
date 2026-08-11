import compression from "compression";
import express from "express";
import helmet from "helmet";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const clientDist = path.resolve(__dirname, "../client/dist");
const indexFile = path.join(clientDist, "index.html");

const SPECIMEN_ID = "SR-2026-08-0147-A3";

const specimenRecord = Object.freeze({
  recordId: SPECIMEN_ID,
  classification: "Live capture - substructure / site condition",
  project: "Riverside Business Park - Block C",
  description:
    "Standing water in blockwork footings after overnight rainfall - grid A/1-D/4",
  file: "IMG_2417.JPG",
  captureMode: "In-app camera only - gallery import blocked",
  capturedAt: "2026-08-10T11:47:03.000Z",
  qualifiedAt: "2026-08-10T11:47:09.000Z",
  position: "50.6412 N, 5.5710 E (+/- 4 m)",
  sha256:
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
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

function normalizeRecordId(value) {
  return String(value ?? "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "");
}

export function createApp() {
  const app = express();

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
  app.use(express.json({ limit: "16kb" }));

  app.use("/api", (_request, response, next) => {
    response.set("Cache-Control", "no-store");
    next();
  });

  app.get("/api/health", (_request, response) => {
    response.status(200).json({
      ok: true,
      service: "sitesealed",
      version: "1.0.0",
    });
  });

  const verifyRecord = (request, response) => {
    const recordId = normalizeRecordId(
      request.params.recordId ?? request.body?.recordId,
    );

    if (!recordId || recordId.length > 64) {
      return response.status(400).json({
        ok: false,
        code: "INVALID_RECORD_ID",
        message: "Enter a valid SiteSealed record ID.",
      });
    }

    if (recordId !== SPECIMEN_ID) {
      return response.status(404).json({
        ok: false,
        code: "RECORD_NOT_FOUND",
        message:
          "This Genesis demo recognises only the specimen record SR-2026-08-0147-A3.",
      });
    }

    return response.status(200).json({
      ok: true,
      specimen: true,
      status: "SPECIMEN_CHECK_PASSED",
      checkedAt: new Date().toISOString(),
      record: specimenRecord,
      scope: {
        proves:
          "The production design will verify existence, integrity and certified time against independent proof rails.",
        doesNotProve:
          "This simulated report is not a certified document and does not prove that the depicted scene was unstaged.",
      },
    });
  };

  app.get("/api/verify/:recordId", verifyRecord);
  app.post("/api/verify", verifyRecord);

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
          if (filePath.endsWith(".html")) {
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

export function startServer() {
  const port = parsePort(process.env.PORT);
  const host = process.env.HOST || "0.0.0.0";
  const app = createApp();
  const server = app.listen(port, host, () => {
    console.log(`SiteSealed listening on ${host}:${port}`);
  });

  const shutdown = (signal) => {
    console.log(`${signal} received; closing HTTP server.`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.once("SIGTERM", () => shutdown("SIGTERM"));
  process.once("SIGINT", () => shutdown("SIGINT"));
  return server;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  startServer();
}
