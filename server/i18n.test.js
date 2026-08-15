import assert from "node:assert/strict";
import { File } from "node:buffer";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer as createViteServer } from "vite";
import {
  PDFArray,
  PDFDict,
  PDFDocument,
  PDFName,
  PDFRawStream,
  decodePDFRawStream,
} from "pdf-lib";
import {
  DEFAULT_LOCALE,
  SUPPORTED_LOCALES,
  catalogDiagnostics,
  detectLocale,
  formatBytes,
  googleLocaleFor,
  localizeScope,
  normalizeLocale,
  translate,
  translateSource,
} from "../client/src/i18n/index.js";
import { generateSiteSealedEvidenceReport } from "../client/src/evidence-report.js";
import { sha256File } from "../client/src/sealing.js";

async function extractAttachments(bytes) {
  const document = await PDFDocument.load(bytes);
  const names = document.catalog.lookup(PDFName.of("Names"), PDFDict);
  const embeddedFiles = names.lookup(PDFName.of("EmbeddedFiles"), PDFDict);
  const entries = embeddedFiles.lookup(PDFName.of("Names"), PDFArray);
  const attachments = new Map();
  for (let index = 0; index < entries.size(); index += 2) {
    const name = entries.lookup(index).decodeText();
    const fileSpec = entries.lookup(index + 1, PDFDict);
    const streams = fileSpec.lookup(PDFName.of("EF"), PDFDict);
    const stream = streams.lookup(PDFName.of("F"), PDFRawStream);
    attachments.set(name, decodePDFRawStream(stream).decode());
  }
  return { document, attachments };
}

test("i18n exposes exactly the five release locales with deterministic detection", () => {
  assert.equal(DEFAULT_LOCALE, "en-US");
  assert.deepEqual(SUPPORTED_LOCALES, [
    "en-US",
    "fr-BE",
    "nl-BE",
    "de-DE",
    "pt-BR",
  ]);
  assert.equal(normalizeLocale("pt"), "pt-BR");
  assert.equal(normalizeLocale("nl_NL"), "nl-BE");
  assert.equal(normalizeLocale("es-ES"), "en-US");
  assert.equal(
    detectLocale({ search: "?lang=de-DE", stored: "fr-BE", languages: ["pt-BR"] }),
    "de-DE",
  );
  assert.equal(
    detectLocale({ stored: "fr-BE", languages: ["pt-BR"] }),
    "fr-BE",
  );
});

test("every locale catalog is structurally complete and translates critical surfaces", () => {
  for (const [locale, diagnostics] of Object.entries(catalogDiagnostics())) {
    assert.deepEqual(diagnostics.missing, [], `${locale} has missing message IDs`);
    assert.deepEqual(diagnostics.extra, [], `${locale} has unexpected message IDs`);
  }

  const criticalIds = [
    "nav.create",
    "google.continueBeforeUpload",
    "workbench.version",
    "workbench.liveTitle",
    "verify.version",
    "verify.downloadReport",
    "scope.live.limit",
    "report.title",
    "report.section.binding",
    "report.locationSource",
    "report.footerAlpha",
  ];
  for (const locale of SUPPORTED_LOCALES.filter((value) => value !== "en-US")) {
    for (const id of criticalIds) {
      assert.notEqual(
        translate(locale, id),
        translate("en-US", id),
        `${locale} must translate ${id}`,
      );
    }
  }
});

test("buyer-facing release labels omit software version numbers", () => {
  const publicIds = [
    "seal.maxSize",
    "workbench.version",
    "verify.version",
    "verify.recordFound",
    "landing.workflowCopy",
    "footer.mvp",
  ];
  for (const locale of SUPPORTED_LOCALES) {
    for (const id of publicIds) {
      assert.doesNotMatch(
        translate(locale, id),
        /\bv?\d+\.\d+(?:\.\d+)?(?:[- ]?alpha(?:\.\d+)?)?/i,
        `${locale} exposes a software version in ${id}`,
      );
    }
    assert.match(translate(locale, "status.version"), /1\.6/);
  }
});

test("source messages, templates, locale formatting and Google locale mapping are stable", () => {
  assert.equal(translateSource("fr-BE", "Verify record"), "Vérifier l’enregistrement");
  assert.equal(
    translateSource("pt-BR", "Block 123 — finalized"),
    "Bloco 123 — finalized",
  );
  assert.equal(formatBytes("fr-BE", 1536), "1,5 Ko");
  assert.equal(formatBytes("en-US", 1536), "1.5 KB");
  assert.equal(googleLocaleFor("pt-BR"), "pt_BR");
  assert.equal(googleLocaleFor("de-DE"), "de_DE");
});

test("the complete React application renders its critical surfaces in every locale", async () => {
  const vite = await createViteServer({
    appType: "custom",
    logLevel: "silent",
    root: fileURLToPath(new URL("..", import.meta.url)),
    server: { middlewareMode: true },
  });
  const previousWindow = globalThis.window;
  try {
    const { default: App } = await vite.ssrLoadModule("/client/src/App.jsx");
    const { I18nProvider } = await vite.ssrLoadModule(
      "/client/src/i18n/I18nProvider.jsx",
    );
    for (const locale of SUPPORTED_LOCALES) {
      globalThis.window = {
        location: {
          href: `https://app.sitesealed.com/?lang=${locale}`,
          pathname: "/",
          search: `?lang=${locale}`,
        },
        localStorage: { getItem: () => "", setItem: () => {} },
        navigator: { languages: [locale], language: locale },
        history: { state: null, replaceState: () => {} },
      };
      const html = renderToStaticMarkup(
        createElement(I18nProvider, null, createElement(App)),
      );
      for (const id of [
        "nav.create",
        "landing.headlineA",
        "workbench.liveTitle",
        "verify.subtitle",
        "status.subtitle",
        "footer.back",
      ]) {
        assert.ok(html.includes(translate(locale, id)), `${locale} did not render ${id}`);
      }
      assert.match(html, new RegExp(`<option value="${locale}" selected="">`));
    }
  } finally {
    globalThis.window = previousWindow;
    await vite.close();
  }
});

test("honest scope is reconstructed in the selected locale without translating proof data", () => {
  const verification = {
    record: {
      recordClass: "LIVE_CAPTURE_WEB",
      storage: { state: "STORED_ENCRYPTED" },
      qualifiedRail: {
        state: "SANDBOX_TOKEN_ISSUED",
        signatureVerification: "VALID",
        certificateChainVerification: "VALID_TO_PINNED_SANDBOX_ROOT",
      },
      chainRail: { state: "FINALIZED", transactionHash: `0x${"a".repeat(64)}` },
    },
  };
  const french = localizeScope("fr-BE", verification);
  const portuguese = localizeScope("pt-BR", verification);
  assert.match(french.doesNotProve, /pixels/);
  assert.match(portuguese.doesNotProve, /pixels/);
  assert.notEqual(french.proves, portuguese.proves);
  assert.equal(verification.record.chainRail.transactionHash, `0x${"a".repeat(64)}`);
});

test("the canonical Evidence Report is generated and tagged in every supported locale", async () => {
  const originalBytes = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Z0kYAAAAASUVORK5CYII=",
    "base64",
  );
  const originalFile = new File([originalBytes], "inspection-école.png", {
    type: "image/png",
    lastModified: Date.parse("2026-08-14T12:00:00.000Z"),
  });
  const recordId = "SR-20260814-I18N";
  const verification = {
    alphaComplete: true,
    record: {
      recordId,
      recordClass: "IMPORTED_FILE",
      sha256: await sha256File(originalFile),
      manifestSha256: "1".repeat(64),
      evidenceDigest: "2".repeat(64),
      receivedAt: "2026-08-14T12:01:00.000Z",
      storage: { state: "STORED_ENCRYPTED" },
      qualifiedRail: {
        state: "SANDBOX_TOKEN_ISSUED",
        signatureVerification: "VALID",
        certificateChainVerification: "VALID_TO_PINNED_SANDBOX_ROOT",
      },
      chainRail: { state: "FINALIZED", block: 23_456_789 },
    },
  };

  for (const locale of SUPPORTED_LOCALES) {
    const bytes = await generateSiteSealedEvidenceReport({
      originalFile,
      verification,
      proofBundle: { recordId, state: "ALPHA_DUAL_RAIL_COMPLETE" },
      generatedAt: new Date("2026-08-14T12:05:00.000Z"),
      locale,
    });
    const { document, attachments } = await extractAttachments(bytes);
    assert.equal(document.getPageCount(), 2);
    assert.equal(
      document.getTitle(),
      `${translate(locale, "report.title")} — SiteSealed ${recordId}`,
    );
    assert.equal(document.getAuthor(), translate(locale, "report.metadata.author"));
    assert.equal(document.getCreator(), translate(locale, "report.metadata.creator"));
    assert.doesNotMatch(document.getCreator(), /1\.6|alpha/i);
    assert.deepEqual(
      Buffer.from(attachments.get("SiteSealed_ORIGINAL_inspection-école.png")),
      originalBytes,
    );
    const manifest = JSON.parse(
      Buffer.from(
        attachments.get(`SiteSealed_${recordId}_report-manifest.json`),
      ).toString("utf8"),
    );
    assert.equal(manifest.locale, locale);
    assert.equal(manifest.generatorVersion, "1.6.0-alpha.2");
    assert.equal(manifest.original.sha256, verification.record.sha256);
  }
});
