import PDFDocument from "pdfkit";

const COLORS = {
  navy: "#0B2942",
  navyDark: "#061A2B",
  amber: "#F39A12",
  green: "#2A8967",
  red: "#A84444",
  paper: "#F4F1EA",
  ink: "#10283B",
  muted: "#667581",
  line: "#D9DFE2",
  white: "#FFFFFF",
};

function formatUtc(value) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "Unavailable";
  return `${date.toISOString().replace("T", " ").replace(".000Z", " UTC")}`;
}

function digestLines(value) {
  const text = String(value ?? "Unavailable");
  return text.length === 64 ? `${text.slice(0, 32)}\n${text.slice(32)}` : text;
}

function sectionTitle(doc, number, title, y) {
  doc
    .font("Helvetica-Bold")
    .fontSize(8.5)
    .fillColor(COLORS.navy)
    .text(`${number}. ${title}`, 40, y, { characterSpacing: 1.4 });
  doc
    .moveTo(40, y + 15)
    .lineTo(150, y + 15)
    .lineWidth(1.2)
    .strokeColor(COLORS.amber)
    .stroke();
}

function labelValue(doc, label, value, x, y, width, options = {}) {
  doc
    .font("Helvetica-Bold")
    .fontSize(6.8)
    .fillColor(COLORS.muted)
    .text(label.toUpperCase(), x, y, { width: 88, characterSpacing: 0.7 });
  doc
    .font(options.mono ? "Courier" : "Helvetica")
    .fontSize(options.mono ? 7.7 : 8.3)
    .fillColor(COLORS.ink)
    .text(value, x + 90, y - 0.5, {
      width: width - 90,
      lineGap: options.lineGap ?? 1.8,
    });
}

function proofCard(doc, { x, y, width, title, state, description, color }) {
  doc
    .save()
    .fillOpacity(0.08)
    .roundedRect(x, y, width, 83, 5)
    .fill(color)
    .restore();
  doc
    .roundedRect(x, y, width, 83, 5)
    .lineWidth(1)
    .strokeColor(color)
    .stroke();
  doc
    .font("Helvetica-Bold")
    .fontSize(7.4)
    .fillColor(color)
    .text(title, x + 13, y + 12, { characterSpacing: 0.9 });
  doc
    .font("Helvetica-Bold")
    .fontSize(10)
    .fillColor(COLORS.ink)
    .text(state, x + 13, y + 30, { width: width - 26 });
  doc
    .font("Helvetica")
    .fontSize(7.4)
    .fillColor(COLORS.muted)
    .text(description, x + 13, y + 48, {
      width: width - 26,
      lineGap: 1.5,
    });
}

function qualifiedProofCopy(record) {
  const rail = record.qualifiedRail ?? {};
  if (rail.state === "SANDBOX_TOKEN_ISSUED") {
    return {
      state: "SANDBOX TOKEN",
      description: `Evidency RFC 3161 test token ${rail.serialNumber ?? "issued"}. Test-only; no qualified eIDAS legal effect.`,
    };
  }
  return {
    state: "NOT ISSUED",
    description:
      "No Evidency RFC 3161 token is attached. The server receipt time has no eIDAS presumption.",
  };
}

function chainProofCopy(record) {
  const rail = record.chainRail ?? {};
  if (rail.state === "INVALID_ON_CHAIN" || rail.state === "FAILED_ON_CHAIN") {
    return {
      state: "REJECTED",
      description:
        rail.state === "INVALID_ON_CHAIN"
          ? "The Ethereum transaction did not match the expected sender or Merkle-root calldata."
          : "The Ethereum transaction failed on-chain and is not a valid anchor.",
    };
  }
  if (rail.state === "FINALIZED") {
    return {
      state: "FINALIZED",
      description: `Ethereum mainnet block ${rail.block ?? "recorded"}; Merkle inclusion path attached and finalized.`,
    };
  }
  if (rail.state === "CONFIRMED" || rail.state === "SUBMITTED") {
    return {
      state: rail.state,
      description: `Ethereum mainnet transaction ${rail.anchor?.slice(0, 18) ?? "submitted"}...; finality pending.`,
    };
  }
  return {
    state: "NOT ANCHORED",
    description:
      "No Ethereum mainnet Merkle transaction is attached to this alpha receipt.",
  };
}

export function renderReceiptPdf(record, { baseUrl }) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: "LETTER",
      margins: { top: 0, right: 0, bottom: 0, left: 0 },
      info: {
        Title: `SiteSealed dual-rail alpha receipt ${record.recordId}`,
        Author: "The SiteSealed Project",
        Subject: "Dual-rail alpha receipt - sandbox timestamp is not legally qualified",
        Creator: "SiteSealed v1.4-alpha.5",
      },
      compress: true,
    });
    const chunks = [];
    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("error", reject);
    doc.on("end", () => resolve(Buffer.concat(chunks)));

    doc.rect(0, 0, 612, 86).fill(COLORS.navy);
    doc.rect(0, 84, 612, 2).fill(COLORS.amber);
    doc
      .circle(57, 41, 18)
      .lineWidth(1.2)
      .strokeColor(COLORS.amber)
      .stroke();
    doc
      .font("Helvetica-Bold")
      .fontSize(8)
      .fillColor(COLORS.amber)
      .text("SS", 48, 37.5, { width: 18, align: "center" });
    doc
      .font("Helvetica-Bold")
      .fontSize(15)
      .fillColor(COLORS.white)
      .text("DUAL-RAIL ALPHA RECEIPT", 88, 24, { characterSpacing: 1.8 });
    doc
      .font("Helvetica")
      .fontSize(7.3)
      .fillColor("#B9C6CF")
      .text(`SiteSealed v1.4-alpha.5 | ${record.recordId}`, 88, 49);
    doc
      .roundedRect(454, 25, 118, 31, 4)
      .lineWidth(1)
      .strokeColor(COLORS.amber)
      .stroke();
    doc
      .font("Helvetica-Bold")
      .fontSize(6.8)
      .fillColor(COLORS.amber)
      .text("ALPHA / NOT SEALED", 454, 37, {
        width: 118,
        align: "center",
        characterSpacing: 0.8,
      });

    sectionTitle(doc, "1", "RECORD", 107);
    labelValue(doc, "Record ID", record.recordId, 40, 132, 532, { mono: true });
    labelValue(doc, "Class", "Imported file - web workflow", 40, 153, 532);
    labelValue(doc, "Received", formatUtc(record.receivedAt), 40, 174, 532);
    labelValue(doc, "Capture claim", "None. This is not a live in-app capture.", 40, 195, 532);

    sectionTitle(doc, "2", "CRYPTOGRAPHIC DIGESTS", 229);
    labelValue(doc, "File SHA-256", digestLines(record.sha256), 40, 252, 532, {
      mono: true,
      lineGap: 1,
    });
    labelValue(
      doc,
      "Manifest SHA-256",
      digestLines(record.manifestSha256),
      40,
      286,
      532,
      { mono: true, lineGap: 1 },
    );
    labelValue(
      doc,
      "Cipher SHA-256",
      digestLines(record.storage?.ciphertextSha256),
      40,
      320,
      532,
      { mono: true, lineGap: 1 },
    );
    labelValue(
      doc,
      "Receipt SHA-256",
      digestLines(record.receiptSha256),
      40,
      354,
      532,
      { mono: true, lineGap: 1 },
    );
    labelValue(
      doc,
      "Evidence digest",
      digestLines(record.evidenceDigest),
      40,
      382,
      532,
      { mono: true, lineGap: 1 },
    );
    doc
      .font("Helvetica")
      .fontSize(7.5)
      .fillColor(COLORS.muted)
      .text(
        "The plaintext original never left the browser. Its ciphertext and the manifest were encrypted with AES-256-GCM under a client-held key; only ciphertext was stored privately.",
        130,
        416,
        { width: 442, lineGap: 1.5 },
      );

    sectionTitle(doc, "3", "EXTERNAL PROOF STATUS", 445);
    const qualified = qualifiedProofCopy(record);
    const chain = chainProofCopy(record);
    proofCard(doc, {
      x: 40,
      y: 470,
      width: 257,
      title: "RAIL A - RFC 3161 TIME",
      state: qualified.state,
      description: qualified.description,
      color: COLORS.green,
    });
    proofCard(doc, {
      x: 315,
      y: 470,
      width: 257,
      title: "RAIL B - PUBLIC CHAIN",
      state: chain.state,
      description: chain.description,
      color: chain.state === "REJECTED" ? COLORS.red : COLORS.amber,
    });

    sectionTitle(doc, "4", "HONEST SCOPE", 567);
    doc
      .roundedRect(40, 590, 532, 96, 5)
      .fillAndStroke(COLORS.paper, COLORS.line);
    doc
      .font("Helvetica-Bold")
      .fontSize(7.6)
      .fillColor(COLORS.ink)
      .text("WHAT THIS RECEIPT CAN SHOW", 53, 602, { characterSpacing: 0.5 });
    doc
      .font("Helvetica")
      .fontSize(7.1)
      .fillColor(COLORS.ink)
      .text(
        "A locally recalculated matching SHA-256 shows byte identity with this receipt. The cards above list only the external artefacts actually attached; absence remains explicit.",
        53,
        618,
        { width: 506, lineGap: 1.1 },
      );
    doc
      .font("Helvetica-Bold")
      .fontSize(7.6)
      .fillColor(COLORS.red)
      .text("NON-NEGOTIABLE LIMIT", 53, 651, { characterSpacing: 0.5 });
    doc
      .font("Helvetica")
      .fontSize(6.8)
      .fillColor(COLORS.ink)
      .text(
        "Evidency sandbox tokens are test-only and cannot support a QUALIFIED or SEALED status. Imported files also carry no live-capture, identity, location or truthfulness attestation.",
        53,
        666,
        { width: 506, lineGap: 1.0 },
      );

    const verificationUrl = `${String(baseUrl).replace(/\/$/, "")}/verify/${encodeURIComponent(record.recordId)}`;
    doc
      .font("Helvetica-Bold")
      .fontSize(7.4)
      .fillColor(COLORS.navy)
      .text("VERIFY LOCALLY - NO FILE UPLOAD", 40, 704, { characterSpacing: 0.7 });
    doc
      .font("Courier")
      .fontSize(7.2)
      .fillColor(COLORS.navy)
      .text(verificationUrl, 40, 721, { width: 532, link: verificationUrl });
    doc
      .font("Helvetica")
      .fontSize(6.9)
      .fillColor(COLORS.muted)
      .text(
        "Select the independently held original in the verifier. Its SHA-256 is recalculated in the browser and is not uploaded.",
        40,
        740,
        { width: 532 },
      );

    doc.rect(0, 759, 612, 33).fill(COLORS.navyDark);
    doc
      .font("Helvetica")
      .fontSize(6.2)
      .fillColor("#B9C6CF")
      .text("SITESEALED - Every alpha receipt declares its proof state.", 40, 771);
    doc
      .font("Helvetica-Bold")
      .fillColor(COLORS.amber)
      .text("ALPHA - NOT A CERTIFIED EVIDENCE REPORT", 330, 771, {
        width: 212,
        align: "right",
        characterSpacing: 0.5,
      });

    doc.end();
  });
}
