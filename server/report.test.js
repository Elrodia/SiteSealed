import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const { version: PACKAGE_VERSION } = require("../package.json");

class TestPdfDocument {
  static instances = [];

  constructor(options) {
    this.options = options;
    this.rendered = [];
    this.pages = 1;
    this.handlers = new Map();
    TestPdfDocument.instances.push(this);
  }

  on(event, handler) {
    this.handlers.set(event, handler);
    return this;
  }

  text(value) {
    this.rendered.push(String(value));
    return this;
  }

  heightOfString(value, { width = 414, lineGap = 1.2 } = {}) {
    const charactersPerLine = Math.max(1, Math.floor(width / 4.5));
    const lines = String(value)
      .split("\n")
      .reduce(
        (count, line) =>
          count + Math.max(1, Math.ceil(line.length / charactersPerLine)),
        0,
      );
    return lines * 8 + Math.max(0, lines - 1) * lineGap;
  }

  addPage() {
    this.pages += 1;
    return this;
  }

  end() {
    this.handlers.get("data")?.(Buffer.from("%PDF-TEST"));
    this.handlers.get("end")?.();
    return this;
  }

  rect() { return this; }
  fill() { return this; }
  circle() { return this; }
  lineWidth() { return this; }
  strokeColor() { return this; }
  stroke() { return this; }
  font() { return this; }
  fontSize() { return this; }
  fillColor() { return this; }
  moveTo() { return this; }
  lineTo() { return this; }
  save() { return this; }
  fillOpacity() { return this; }
  roundedRect() { return this; }
  restore() { return this; }
  fillAndStroke() { return this; }
}

const reportSource = await readFile(new URL("./report.js", import.meta.url), "utf8");
const instrumentedSource = reportSource
  .replace('import { createRequire } from "node:module";\n', "")
  .replace(
    'import PDFDocument from "pdfkit";',
    "const PDFDocument = globalThis.__SiteSealedTestPdfDocument;",
  )
  .replace(
    'const require = createRequire(import.meta.url);\nconst { version: PACKAGE_VERSION } = require("../package.json");',
    `const PACKAGE_VERSION = ${JSON.stringify(PACKAGE_VERSION)};`,
  );
assert.notEqual(instrumentedSource, reportSource);
globalThis.__SiteSealedTestPdfDocument = TestPdfDocument;
const { renderReceiptPdf } = await import(
  `data:text/javascript;base64,${Buffer.from(instrumentedSource).toString("base64")}`
);
delete globalThis.__SiteSealedTestPdfDocument;

function finalizedRecord({ inclusionPathLength = 18 } = {}) {
  return {
    recordId: "SR-20260821-REPORTPROOFDETAILS000001",
    receivedAt: "2026-08-21T09:30:00.000Z",
    sha256: "1".repeat(64),
    manifestSha256: "2".repeat(64),
    receiptSha256: "3".repeat(64),
    evidenceDigest: "4".repeat(64),
    storage: { ciphertextSha256: "5".repeat(64) },
    qualifiedRail: { state: "NOT_ISSUED" },
    chainRail: {
      state: "FINALIZED",
      anchor: `0x${"a".repeat(64)}`,
      anchorAddress: `0x${"b".repeat(40)}`,
      block: "25,748,941",
      chainId: 1,
      merkleRoot: "c".repeat(64),
      merkleProtocol: "SITESEALED_MERKLE_SHA256_V1",
      leafHash: "d".repeat(64),
      leafIndex: 7,
      batchSize: 1_024,
      inclusionPath: Array.from({ length: inclusionPathLength }, (_, index) => ({
        position: index % 2 === 0 ? "left" : "right",
        sha256: (index + 16).toString(16).padStart(64, "0"),
      })),
    },
  };
}

async function captureRenderedText(record) {
  TestPdfDocument.instances.length = 0;
  const pdf = await renderReceiptPdf(record, {
    baseUrl: "https://app.sitesealed.com",
  });
  const document = TestPdfDocument.instances.at(-1);
  assert.ok(document);
  return { pdf, rendered: document.rendered, document };
}

function withoutLayoutWhitespace(rendered) {
  return rendered.join("\n").replaceAll(/\s/g, "");
}

test("a FINALIZED report renders the complete public-chain proof and every inclusion step", async () => {
  const record = finalizedRecord();
  const { rendered, document } = await captureRenderedText(record);
  const compact = withoutLayoutWhitespace(rendered);

  assert.ok(compact.includes(record.chainRail.anchor));
  assert.ok(compact.includes(record.chainRail.anchorAddress));
  assert.ok(compact.includes(record.chainRail.merkleRoot));
  assert.ok(compact.includes(record.chainRail.leafHash));
  assert.ok(rendered.includes("BLOCK"));
  assert.ok(rendered.includes("25,748,941 | chainId 1"));
  assert.ok(rendered.includes("MERKLE.PROTOCOL"));
  assert.ok(rendered.includes(record.chainRail.merkleProtocol));
  assert.ok(
    rendered.some((value) => value.includes("leafIndex 7 of batchSize 1024")),
  );
  assert.ok(rendered.includes("VERIFY WITHOUT SITESEALED"));

  record.chainRail.inclusionPath.forEach((entry, index) => {
    assert.ok(compact.includes(entry.sha256));
    assert.ok(
      rendered.includes(`PATH[${index}] ${entry.position.toUpperCase()}`),
    );
  });

  assert.ok(document.pages > 1, "the long inclusion path must flow to another page");
});

test("a FINALIZED report never ellipsis-truncates a proof hash", async () => {
  const record = finalizedRecord({ inclusionPathLength: 4 });
  const { rendered } = await captureRenderedText(record);
  const compact = withoutLayoutWhitespace(rendered);

  assert.ok(compact.includes(record.chainRail.anchor));
  assert.ok(compact.includes(record.chainRail.merkleRoot));
  assert.ok(compact.includes(record.chainRail.leafHash));
  assert.equal(rendered.some((value) => value.includes("...")), false);
  assert.equal(rendered.some((value) => value.includes("…")), false);
});

test("a null anchor keeps the existing NOT ANCHORED presentation", async () => {
  const record = finalizedRecord({ inclusionPathLength: 0 });
  record.chainRail = {
    state: "NOT_ANCHORED",
    anchor: null,
  };

  const { pdf, rendered } = await captureRenderedText(record);
  assert.ok(pdf.length > 0);
  assert.ok(rendered.includes("NOT ANCHORED"));
  assert.ok(
    rendered.includes(
      "No Ethereum mainnet Merkle transaction is attached to this alpha receipt.",
    ),
  );
  assert.equal(rendered.includes("VERIFY WITHOUT SITESEALED"), false);
});

test("PDF metadata Creator follows the package version", async () => {
  const { document } = await captureRenderedText(
    finalizedRecord({ inclusionPathLength: 0 }),
  );
  assert.equal(
    document.options.info.Creator,
    `SiteSealed v${PACKAGE_VERSION}`,
  );
});
