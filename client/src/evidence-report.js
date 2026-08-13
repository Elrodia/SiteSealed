import {
  AFRelationship,
  PDFDocument,
  StandardFonts,
  rgb,
} from "pdf-lib";
import { sha256File } from "./sealing.js";

const RELEASE = "1.4.0-alpha.10";
const PAGE_WIDTH = 612;
const PAGE_HEIGHT = 792;
const COLORS = {
  navy: rgb(11 / 255, 41 / 255, 66 / 255),
  navyDark: rgb(6 / 255, 26 / 255, 43 / 255),
  amber: rgb(243 / 255, 154 / 255, 18 / 255),
  amberSoft: rgb(252 / 255, 245 / 255, 232 / 255),
  green: rgb(42 / 255, 137 / 255, 103 / 255),
  greenSoft: rgb(236 / 255, 247 / 255, 242 / 255),
  red: rgb(168 / 255, 68 / 255, 68 / 255),
  paper: rgb(244 / 255, 241 / 255, 234 / 255),
  ink: rgb(16 / 255, 40 / 255, 59 / 255),
  muted: rgb(102 / 255, 117 / 255, 129 / 255),
  line: rgb(217 / 255, 223 / 255, 226 / 255),
  white: rgb(1, 1, 1),
};

function printable(value, fallback = "Unavailable") {
  const normalized = String(value ?? "").trim();
  if (!normalized) return fallback;
  return normalized
    .replace(/[\u2010-\u2015]/g, "-")
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^\x20-\x7e]/g, "?");
}

function attachmentName(value, fallback) {
  const name = String(value ?? "")
    .replace(/[\\/\0]/g, "_")
    .trim();
  return (name || fallback).slice(0, 180);
}

function formatBytes(bytes) {
  const value = Number(bytes ?? 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
}

function formatUtc(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? "Unavailable"
    : date.toISOString().replace("T", " ").replace(".000Z", "Z");
}

function wrapText(text, font, size, maxWidth, maxLines = Infinity) {
  const words = printable(text).split(/\s+/).filter(Boolean);
  const lines = [];
  let line = "";

  const pushLongWord = (word) => {
    let segment = "";
    for (const character of word) {
      const candidate = `${segment}${character}`;
      if (segment && font.widthOfTextAtSize(candidate, size) > maxWidth) {
        lines.push(segment);
        segment = character;
        if (lines.length >= maxLines) return "";
      } else {
        segment = candidate;
      }
    }
    return segment;
  };

  for (const word of words) {
    if (lines.length >= maxLines) break;
    const candidate = line ? `${line} ${word}` : word;
    if (font.widthOfTextAtSize(candidate, size) <= maxWidth) {
      line = candidate;
      continue;
    }
    if (line) {
      lines.push(line);
      line = "";
      if (lines.length >= maxLines) break;
    }
    if (font.widthOfTextAtSize(word, size) <= maxWidth) {
      line = word;
    } else {
      line = pushLongWord(word);
    }
  }
  if (line && lines.length < maxLines) lines.push(line);
  return lines;
}

function drawWrapped(page, text, {
  x,
  y,
  width,
  font,
  size,
  color = COLORS.ink,
  lineHeight = size * 1.3,
  maxLines = Infinity,
}) {
  const lines = wrapText(text, font, size, width, maxLines);
  lines.forEach((line, index) => {
    page.drawText(line, {
      x,
      y: y - index * lineHeight,
      font,
      size,
      color,
    });
  });
  return y - lines.length * lineHeight;
}

function drawSection(page, fonts, number, title, y) {
  page.drawText(`${number}. ${title}`, {
    x: 40,
    y,
    font: fonts.bold,
    size: 9,
    color: COLORS.navy,
  });
  page.drawLine({
    start: { x: 40, y: y - 8 },
    end: { x: 165, y: y - 8 },
    thickness: 1.4,
    color: COLORS.amber,
  });
}

function reportState(verification) {
  const record = verification?.record ?? {};
  if (verification?.alphaComplete) return "ALPHA DUAL RAIL COMPLETE";
  if (record.chainRail?.state === "FINALIZED") {
    return "MAINNET FINALIZED / TIME PENDING";
  }
  if (record.qualifiedRail?.state === "SANDBOX_TOKEN_ISSUED") {
    return "SANDBOX VERIFIED / MAINNET PENDING";
  }
  return "EXTERNAL PROOFS PENDING";
}

function drawHeader(page, fonts, recordId, state, pageNumber) {
  page.drawRectangle({
    x: 0,
    y: 700,
    width: PAGE_WIDTH,
    height: 92,
    color: COLORS.navy,
  });
  page.drawRectangle({
    x: 0,
    y: 697,
    width: PAGE_WIDTH,
    height: 3,
    color: COLORS.amber,
  });
  page.drawCircle({
    x: 58,
    y: 746,
    size: 21,
    borderColor: COLORS.amber,
    borderWidth: 1.5,
  });
  page.drawText("SS", {
    x: 49.5,
    y: 742.5,
    font: fonts.bold,
    size: 8,
    color: COLORS.amber,
  });
  page.drawText("EVIDENCE REPORT", {
    x: 92,
    y: 750,
    font: fonts.bold,
    size: 16,
    color: COLORS.white,
  });
  page.drawText(`SiteSealed ${RELEASE} | ${printable(recordId)}`, {
    x: 92,
    y: 729,
    font: fonts.regular,
    size: 7.3,
    color: rgb(185 / 255, 198 / 255, 207 / 255),
  });
  page.drawRectangle({
    x: 410,
    y: 730,
    width: 162,
    height: 34,
    borderColor: COLORS.amber,
    borderWidth: 1,
  });
  const badge = printable(state).slice(0, 40);
  page.drawText(badge, {
    x: 419,
    y: 743,
    width: 144,
    font: fonts.bold,
    size: 6.4,
    color: COLORS.amber,
  });
  page.drawText(`PAGE ${pageNumber} / 2`, {
    x: 520,
    y: 710,
    font: fonts.regular,
    size: 5.7,
    color: rgb(185 / 255, 198 / 255, 207 / 255),
  });
}

function drawFooter(page, fonts) {
  page.drawRectangle({
    x: 0,
    y: 0,
    width: PAGE_WIDTH,
    height: 32,
    color: COLORS.navyDark,
  });
  page.drawText("SITESEALED - The exact original is embedded in this report.", {
    x: 40,
    y: 12,
    font: fonts.regular,
    size: 6.1,
    color: rgb(185 / 255, 198 / 255, 207 / 255),
  });
  page.drawText("ALPHA - NOT A QUALIFIED EVIDENCE REPORT", {
    x: 365,
    y: 12,
    font: fonts.bold,
    size: 6.1,
    color: COLORS.amber,
  });
}

function drawContained(page, embedded, frame) {
  const scale = Math.min(frame.width / embedded.width, frame.height / embedded.height);
  const width = embedded.width * scale;
  const height = embedded.height * scale;
  const options = {
    x: frame.x + (frame.width - width) / 2,
    y: frame.y + (frame.height - height) / 2,
    width,
    height,
  };
  if (embedded.kind === "pdf-page") page.drawPage(embedded.value, options);
  else page.drawImage(embedded.value, options);
}

async function browserImagePreview(file) {
  if (
    typeof createImageBitmap !== "function" ||
    typeof document === "undefined" ||
    !String(file.type ?? "").startsWith("image/")
  ) {
    return null;
  }
  const bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
  try {
    const maximum = 1800;
    const scale = Math.min(1, maximum / Math.max(bitmap.width, bitmap.height));
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    const context = canvas.getContext("2d", { alpha: false });
    if (!context) return null;
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    const blob = await new Promise((resolve) =>
      canvas.toBlob(resolve, "image/jpeg", 0.86),
    );
    return blob ? new Uint8Array(await blob.arrayBuffer()) : null;
  } finally {
    bitmap.close();
  }
}

function looksLikeJpeg(bytes) {
  return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
}

function looksLikePng(bytes) {
  return (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47
  );
}

function looksLikePdf(bytes) {
  return bytes.length >= 5 && new TextDecoder("ascii").decode(bytes.slice(0, 5)) === "%PDF-";
}

async function embedPreview(pdf, file, originalBytes) {
  const browserPreview = await browserImagePreview(file).catch(() => null);
  if (browserPreview) {
    const image = await pdf.embedJpg(browserPreview);
    return { kind: "image", value: image, width: image.width, height: image.height };
  }
  if (looksLikeJpeg(originalBytes)) {
    const image = await pdf.embedJpg(originalBytes);
    return { kind: "image", value: image, width: image.width, height: image.height };
  }
  if (looksLikePng(originalBytes)) {
    const image = await pdf.embedPng(originalBytes);
    return { kind: "image", value: image, width: image.width, height: image.height };
  }
  if (looksLikePdf(originalBytes)) {
    const source = await PDFDocument.load(originalBytes, { ignoreEncryption: false });
    if (source.getPageCount() > 0) {
      const [embeddedPage] = await pdf.embedPdf(originalBytes, [0]);
      return {
        kind: "pdf-page",
        value: embeddedPage,
        width: embeddedPage.width,
        height: embeddedPage.height,
      };
    }
  }
  return null;
}

function labelValue(page, fonts, label, value, x, y, width, { mono = false } = {}) {
  page.drawText(printable(label).toUpperCase(), {
    x,
    y,
    font: fonts.bold,
    size: 6.2,
    color: COLORS.muted,
  });
  return drawWrapped(page, value, {
    x,
    y: y - 13,
    width,
    font: mono ? fonts.mono : fonts.regular,
    size: mono ? 7.1 : 7.5,
    color: COLORS.ink,
    lineHeight: mono ? 9 : 10,
    maxLines: mono ? 3 : 4,
  });
}

function drawRailCard(page, fonts, {
  x,
  y,
  width,
  title,
  state,
  description,
  color,
  fill,
}) {
  page.drawRectangle({
    x,
    y,
    width,
    height: 104,
    color: fill,
    borderColor: color,
    borderWidth: 1,
  });
  page.drawText(printable(title), {
    x: x + 13,
    y: y + 80,
    font: fonts.bold,
    size: 7,
    color,
  });
  page.drawText(printable(state), {
    x: x + 13,
    y: y + 59,
    font: fonts.bold,
    size: 10,
    color: COLORS.ink,
  });
  drawWrapped(page, description, {
    x: x + 13,
    y: y + 42,
    width: width - 26,
    font: fonts.regular,
    size: 6.8,
    color: COLORS.muted,
    lineHeight: 8.4,
    maxLines: 4,
  });
}

export async function generateSiteSealedEvidenceReport({
  originalFile,
  verification,
  proofBundle,
  timestampToken = null,
  baseUrl = "https://app.sitesealed.com",
  generatedAt = new Date(),
} = {}) {
  if (!(originalFile instanceof Blob)) {
    throw new TypeError("The exact browser File or Blob is required to generate the Evidence Report.");
  }
  const record = verification?.record;
  if (!record?.recordId || !/^[a-f0-9]{64}$/i.test(String(record.sha256 ?? ""))) {
    throw new Error("A persisted SiteSealed record with a valid original SHA-256 is required.");
  }
  const calculatedSha256 = await sha256File(originalFile);
  if (calculatedSha256 !== String(record.sha256).toLowerCase()) {
    throw new Error("Evidence Report refused: the selected original does not match the recorded SHA-256.");
  }

  const originalBytes = new Uint8Array(await originalFile.arrayBuffer());
  const reportTime = new Date(generatedAt);
  if (Number.isNaN(reportTime.valueOf())) throw new Error("generatedAt must be a valid date.");
  const pdf = await PDFDocument.create();
  pdf.setTitle(`SiteSealed Evidence Report ${record.recordId}`);
  pdf.setAuthor("The SiteSealed Project");
  pdf.setSubject("Evidence Report with exact original file and dual-rail proof artefacts");
  pdf.setCreator(`SiteSealed ${RELEASE} browser report generator`);
  pdf.setProducer("pdf-lib / SiteSealed browser workflow");
  pdf.setCreationDate(reportTime);
  pdf.setModificationDate(reportTime);

  const fonts = {
    regular: await pdf.embedFont(StandardFonts.Helvetica),
    bold: await pdf.embedFont(StandardFonts.HelveticaBold),
    mono: await pdf.embedFont(StandardFonts.Courier),
  };
  const state = reportState(verification);
  const pageOne = pdf.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
  const pageTwo = pdf.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
  drawHeader(pageOne, fonts, record.recordId, state, 1);
  drawHeader(pageTwo, fonts, record.recordId, state, 2);
  drawFooter(pageOne, fonts);
  drawFooter(pageTwo, fonts);

  drawSection(pageOne, fonts, "1", "ORIGINAL RECORD", 672);
  pageOne.drawRectangle({
    x: 40,
    y: 220,
    width: 532,
    height: 420,
    color: rgb(247 / 255, 249 / 255, 249 / 255),
    borderColor: COLORS.line,
    borderWidth: 1,
  });
  const preview = await embedPreview(pdf, originalFile, originalBytes).catch(
    () => null,
  );
  if (preview) {
    drawContained(pageOne, preview, { x: 47, y: 227, width: 518, height: 406 });
  } else {
    pageOne.drawText("VISUAL PREVIEW UNAVAILABLE", {
      x: 178,
      y: 430,
      font: fonts.bold,
      size: 13,
      color: COLORS.muted,
    });
    drawWrapped(pageOne, "The exact uploaded file is nevertheless embedded below as the canonical source attachment.", {
      x: 150,
      y: 407,
      width: 312,
      font: fonts.regular,
      size: 8,
      color: COLORS.muted,
      lineHeight: 11,
      maxLines: 3,
    });
  }

  const sourceName = attachmentName(
    `SiteSealed_ORIGINAL_${originalFile.name || "uploaded-file"}`,
    "SiteSealed_ORIGINAL_uploaded-file.bin",
  );
  pageOne.drawText(printable(originalFile.name || "Uploaded original"), {
    x: 40,
    y: 191,
    font: fonts.bold,
    size: 12,
    color: COLORS.navy,
  });
  pageOne.drawText(
    `${formatBytes(originalBytes.length)} | ${printable(originalFile.type || "application/octet-stream")} | EXACT ORIGINAL ATTACHED`,
    {
      x: 40,
      y: 173,
      font: fonts.regular,
      size: 7.2,
      color: COLORS.green,
    },
  );
  pageOne.drawText("ORIGINAL FILE SHA-256 / BYTE IDENTITY VERIFIED", {
    x: 40,
    y: 147,
    font: fonts.bold,
    size: 6.7,
    color: COLORS.muted,
  });
  pageOne.drawText(calculatedSha256.slice(0, 32), {
    x: 40,
    y: 129,
    font: fonts.mono,
    size: 8.2,
    color: COLORS.ink,
  });
  pageOne.drawText(calculatedSha256.slice(32), {
    x: 40,
    y: 117,
    font: fonts.mono,
    size: 8.2,
    color: COLORS.ink,
  });
  drawWrapped(pageOne, "The displayed image is a presentation preview. The complete, unchanged byte sequence is incorporated in this same PDF as an associated source file.", {
    x: 300,
    y: 147,
    width: 272,
    font: fonts.regular,
    size: 7,
    color: COLORS.muted,
    lineHeight: 9.2,
    maxLines: 5,
  });

  drawSection(pageTwo, fonts, "2", "RECORD AND CRYPTOGRAPHIC BINDING", 672);
  labelValue(pageTwo, fonts, "Record ID", record.recordId, 40, 644, 246, { mono: true });
  labelValue(pageTwo, fonts, "Class", record.classification || "Imported file - web workflow", 315, 644, 257);
  labelValue(pageTwo, fonts, "Received", formatUtc(record.receivedAt), 40, 591, 246);
  labelValue(pageTwo, fonts, "Report generated", formatUtc(reportTime), 315, 591, 257);
  labelValue(pageTwo, fonts, "Manifest SHA-256", record.manifestSha256, 40, 538, 246, { mono: true });
  labelValue(pageTwo, fonts, "Evidence digest", record.evidenceDigest, 315, 538, 257, { mono: true });

  drawSection(pageTwo, fonts, "3", "EXTERNAL PROOF RAILS", 472);
  const qualified = record.qualifiedRail ?? {};
  const qualifiedVerified =
    qualified.state === "SANDBOX_TOKEN_ISSUED" &&
    qualified.signatureVerification === "VALID" &&
    qualified.certificateChainVerification === "VALID_TO_PINNED_SANDBOX_ROOT";
  drawRailCard(pageTwo, fonts, {
    x: 40,
    y: 342,
    width: 257,
    title: "RAIL A - RFC 3161 TIME",
    state: qualifiedVerified ? "SANDBOX / VERIFIED" : printable(qualified.state || "NOT ISSUED"),
    description: qualifiedVerified
      ? "CMS signature and path to the pinned sandbox root verified. Test-only; revocation not checked; no qualified eIDAS effect."
      : qualified.status || "No externally verified timestamp token is attached.",
    color: COLORS.green,
    fill: COLORS.greenSoft,
  });
  const chain = record.chainRail ?? {};
  const chainRejected = ["INVALID_ON_CHAIN", "FAILED_ON_CHAIN"].includes(chain.state);
  drawRailCard(pageTwo, fonts, {
    x: 315,
    y: 342,
    width: 257,
    title: "RAIL B - ETHEREUM MAINNET",
    state: printable(chain.state || "NOT ANCHORED"),
    description:
      chain.state === "FINALIZED"
        ? `Block ${chain.block || chain.blockNumber || "recorded"}; Merkle inclusion and transaction binding verified as finalized.`
        : chain.status || "No public-chain anchor is attached.",
    color: chainRejected ? COLORS.red : COLORS.amber,
    fill: chainRejected ? rgb(1, 0.94, 0.93) : COLORS.amberSoft,
  });

  drawSection(pageTwo, fonts, "4", "HONEST SCOPE", 310);
  pageTwo.drawRectangle({
    x: 40,
    y: 154,
    width: 532,
    height: 126,
    color: COLORS.paper,
    borderColor: COLORS.line,
    borderWidth: 1,
  });
  pageTwo.drawText("WHAT THIS REPORT CAN SHOW", {
    x: 53,
    y: 255,
    font: fonts.bold,
    size: 7.2,
    color: COLORS.navy,
  });
  drawWrapped(pageTwo, verification?.scope?.proves || "The embedded original matches the recorded SHA-256 digest.", {
    x: 53,
    y: 239,
    width: 506,
    font: fonts.regular,
    size: 6.7,
    color: COLORS.ink,
    lineHeight: 8.3,
    maxLines: 5,
  });
  pageTwo.drawText("NON-NEGOTIABLE LIMIT", {
    x: 53,
    y: 193,
    font: fonts.bold,
    size: 7.2,
    color: COLORS.red,
  });
  drawWrapped(pageTwo, verification?.scope?.doesNotProve || "This report does not prove authorship, live capture, location or truthfulness.", {
    x: 53,
    y: 177,
    width: 506,
    font: fonts.regular,
    size: 6.5,
    color: COLORS.ink,
    lineHeight: 8,
    maxLines: 4,
  });

  const verificationUrl = `${String(baseUrl).replace(/\/$/, "")}/verify/${encodeURIComponent(record.recordId)}`;
  pageTwo.drawText("VERIFY THIS RECORD", {
    x: 40,
    y: 126,
    font: fonts.bold,
    size: 7.1,
    color: COLORS.navy,
  });
  pageTwo.drawText(printable(verificationUrl), {
    x: 40,
    y: 111,
    font: fonts.mono,
    size: 6.4,
    color: COLORS.navy,
  });
  drawWrapped(pageTwo, `Embedded sources: ${sourceName}; SiteSealed proof bundle${timestampToken ? "; RFC 3161 token" : ""}.`, {
    x: 40,
    y: 91,
    width: 532,
    font: fonts.regular,
    size: 6.5,
    color: COLORS.muted,
    lineHeight: 8,
    maxLines: 3,
  });

  const proofName = attachmentName(
    `SiteSealed_${record.recordId}_proof-bundle.json`,
    "SiteSealed_proof-bundle.json",
  );
  const proofJson = `${JSON.stringify(proofBundle ?? verification, null, 2)}\n`;
  const proofBytes = new TextEncoder().encode(proofJson);
  const reportManifest = {
    schemaVersion: "sitesealed.evidence-report-manifest.v1",
    generatorVersion: RELEASE,
    generatedAt: reportTime.toISOString(),
    recordId: record.recordId,
    original: {
      attachmentName: sourceName,
      fileName: originalFile.name || "uploaded-file",
      mimeType: originalFile.type || "application/octet-stream",
      byteLength: originalBytes.length,
      sha256: calculatedSha256,
      byteIdentityVerified: true,
    },
    proofBundle: { attachmentName: proofName },
    timestampToken: timestampToken
      ? {
          attachmentName: `SiteSealed_${record.recordId}_timestamp.tsr`,
          sha256: qualified.tokenSha256 ?? null,
        }
      : null,
  };
  const manifestName = `SiteSealed_${record.recordId}_report-manifest.json`;

  await pdf.attach(originalBytes, sourceName, {
    mimeType: originalFile.type || "application/octet-stream",
    description: "Exact byte-for-byte original bound to the recorded SiteSealed SHA-256 digest",
    creationDate:
      Number(originalFile.lastModified) > 0
        ? new Date(originalFile.lastModified)
        : reportTime,
    modificationDate: reportTime,
    afRelationship: AFRelationship.Source,
  });
  await pdf.attach(proofBytes, proofName, {
    mimeType: "application/json",
    description: "SiteSealed public proof bundle",
    creationDate: reportTime,
    modificationDate: reportTime,
    afRelationship: AFRelationship.Data,
  });
  await pdf.attach(
    new TextEncoder().encode(`${JSON.stringify(reportManifest, null, 2)}\n`),
    manifestName,
    {
      mimeType: "application/json",
      description: "Machine-readable manifest for this SiteSealed Evidence Report",
      creationDate: reportTime,
      modificationDate: reportTime,
      afRelationship: AFRelationship.Schema,
    },
  );
  if (timestampToken) {
    await pdf.attach(
      timestampToken,
      `SiteSealed_${record.recordId}_timestamp.tsr`,
      {
        mimeType: "application/timestamp-reply",
        description: "RFC 3161 timestamp response attached to the SiteSealed record",
        creationDate: reportTime,
        modificationDate: reportTime,
        afRelationship: AFRelationship.Data,
      },
    );
  }

  return pdf.save({ useObjectStreams: false });
}

export function evidenceReportFileName(recordId) {
  const safeRecordId = printable(recordId).replace(/[^A-Za-z0-9_-]/g, "_");
  return `SiteSealed_${safeRecordId}_Evidence_Report.pdf`;
}
