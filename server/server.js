import compression from "compression";
import express from "express";
import helmet from "helmet";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createMysqlRecordStoreFromEnv } from "./database.js";
import { createMemoryRecordStore, normalizeRecordId } from "./specimen.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const clientDist = path.resolve(__dirname, "../client/dist");
const indexFile = path.join(clientDist, "index.html");

export function createApp({ recordStore = createMemoryRecordStore() } = {}) {
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

  app.get("/api/health", async (_request, response) => {
    const database = await recordStore.healthCheck();
    response.status(200).json({
      ok: true,
      service: "sitesealed",
      version: "1.1.0",
      database,
    });
  });

  const verifyRecord = async (request, response) => {
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

    const record = await recordStore.findById(recordId);
    if (!record) {
      return response.status(404).json({
        ok: false,
        code: "RECORD_NOT_FOUND",
        message: "No sealed SiteSealed record was found for this identifier.",
      });
    }

    return response.status(200).json({
      ok: true,
      specimen: Boolean(record.specimen),
      status: record.specimen ? "SPECIMEN_CHECK_PASSED" : "CHECK_PASSED",
      checkedAt: new Date().toISOString(),
      record,
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

export async function startServer() {
  const port = parsePort(process.env.PORT);
  const host = process.env.HOST || "0.0.0.0";
  const recordStore =
    (await createMysqlRecordStoreFromEnv(process.env)) ??
    createMemoryRecordStore();
  const app = createApp({ recordStore });
  const server = app.listen(port, host, () => {
    console.log(
      `SiteSealed listening on ${host}:${port} with ${recordStore.mode} records.`,
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
        await recordStore.close();
        clearTimeout(timeout);
        process.exit(0);
      } catch (error) {
        console.error(`Database shutdown failed: ${error.message}`);
        process.exit(1);
      }
    });
  };

  process.once("SIGTERM", () => shutdown("SIGTERM"));
  process.once("SIGINT", () => shutdown("SIGINT"));
  return { server, recordStore };
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
