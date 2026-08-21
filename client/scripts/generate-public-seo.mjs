import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_LOCALE,
  SUPPORTED_LOCALES,
} from "../src/i18n/index.js";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const clientDirectory = path.resolve(scriptDirectory, "..");
const publicDirectory = path.join(clientDirectory, "public");
const distributionDirectory = path.join(clientDirectory, "dist");
const origin = "https://app.sitesealed.com";
const socialImage = `${origin}/sitesealed-social-1200x628.png`;

const publicPages = Object.freeze([
  {
    slug: "how-it-works",
    path: "/how-it-works",
    changefreq: "monthly",
    priority: "0.9",
    title: "How SiteSealed Works | Five-Step Evidence Sealing",
    description: "Understand SiteSealed's five-step construction evidence pipeline, its two independent proof rails and the limits stated by the current web alpha.",
    h1: "How SiteSealed turns a construction record into checkable evidence",
    lede: "SiteSealed follows a five-step path from capture to a portable proof bundle. The design is deliberately explicit about which parts already operate in the web application and which parts remain targets of the founding whitepaper.",
    sections: [
      {
        heading: "1. Capture: preserve the distinction between live and imported material",
        paragraphs: [
          "The first step establishes the record class before any proof is created. A live web capture is produced through the camera interface, linked to a fresh server challenge, a verified SiteSealed account session and browser-reported context. An imported photograph, PDF or other pre-existing file remains a separate class. It is never silently presented as a live capture, because an upload cannot prove when or where the source file was originally made.",
          "The current web client still lacks hardware-backed camera, device, GNSS and clock attestation. Browser geolocation is a claim bound into the manifest, not authenticated satellite positioning. A hostile client can simulate camera input or submit false context outside the official interface. The Evidence Report therefore separates cryptographically proven file identity from server-bound claims and from facts that remain unproved. That boundary is part of the evidence, not a footnote.",
        ],
      },
      {
        heading: "2. Hash and encrypt on the client",
        paragraphs: [
          "The browser computes SHA-256 digests for the exact original and the canonical manifest before upload. A digest is a fixed-length fingerprint: changing even one byte produces a different value. The original and manifest are encrypted with AES-256-GCM in the browser, and the decryption material stays in the private Recovery Kit. The server receives ciphertext and the values needed to bind it to one exact grant; it does not receive the plaintext original or the AES key.",
          "Hashing proves identity and later integrity, but it does not establish truth, authorship or capture time on its own. This is why SiteSealed binds the digest to an explicit record class and a manifest instead of treating a file hash as a complete evidentiary claim. The canonical Evidence Report contains the visible exact original and the exported proof sources so a recipient can perform the same calculations without relying on a screenshot or portal summary.",
        ],
      },
      {
        heading: "3. Request an external time token without overstating it",
        paragraphs: [
          "In the founding design, the digest is submitted to a qualified trust service provider and receives a qualified electronic timestamp. The deployed alpha does not yet meet that condition. It calls Evidency's sandbox and independently checks the returned RFC 3161 token, CMS signature, signer binding and certificate path to a release-pinned sandbox root. The token is test-only, is not qualified and carries no qualified eIDAS legal presumption.",
          "Keeping the qualification boundary visible prevents a technically valid sandbox response from becoming a false legal statement. Moving to production would require a production service agreement, an appropriate trust policy, qualification status verified through the relevant EU Trusted List, certificate revocation handling and a formal security review. Until those gates are met, the interface and reports retain their sandbox and ALPHA wording.",
        ],
      },
      {
        heading: "4. Batch records with a Merkle tree",
        paragraphs: [
          "Evidence digests are grouped into a Merkle tree. Pairwise hashing produces intermediate nodes until one Merkle root commits to the complete batch. Each record keeps its leaf hash, leaf index, batch size and inclusion path. The path contains only the sibling hashes and their left or right position, so a verifier can reconstruct the root without learning the contents or identities of the other records in the batch.",
          "Batching is an efficiency mechanism, not a change to the evidence. One root can commit to many records while every individual record remains independently checkable. The proof bundle records the Merkle protocol and exact path rather than asking a reader to trust a green status label. A mismatch at any step produces a different root and fails verification.",
        ],
      },
      {
        heading: "5. Anchor the root and export one canonical Evidence Report",
        paragraphs: [
          "The hourly rail worker commits the Merkle root to Ethereum mainnet in domain-marked transaction calldata. After the required confirmations and finality checks, the record exposes the full transaction hash, anchor address, chain and block, Merkle root, leaf and inclusion path. Those fields let a reader fetch the transaction from an independent Ethereum node and compare the public commitment with the locally recomputed root.",
          "The final human artefact is one SiteSealed Evidence Report. It contains the visible exact original, attaches the original byte-for-byte, identifies both external rails and states what is proven, attested or not claimed. A finalized chain anchor does not make the content factually true, and a sandbox time token does not become qualified merely because its signature is valid. The report is designed to survive scrutiny by making those limits inseparable from the proof.",
        ],
      },
    ],
  },
  {
    slug: "qualified-timestamping",
    path: "/qualified-timestamping",
    changefreq: "monthly",
    priority: "0.8",
    title: "Qualified Electronic Timestamping | RFC 3161 and eIDAS",
    description: "Learn the difference between an RFC 3161 token and a qualified eIDAS timestamp, including the legal presumption and SiteSealed's sandbox limitation.",
    h1: "Qualified electronic timestamping, RFC 3161 and the current sandbox boundary",
    lede: "A timestamp can be cryptographically valid without being legally qualified. SiteSealed treats format, signature validation, provider status and legal effect as separate questions so that a sandbox token is never advertised as more than it is.",
    sections: [
      {
        heading: "RFC 3161 defines a technical token, not qualification by itself",
        paragraphs: [
          "RFC 3161 describes a protocol in which a time-stamping authority receives a message imprint and returns a signed token binding that digest to a stated time. The original construction file does not need to be disclosed to the authority: SiteSealed sends the evidence digest. A verifier can inspect the token's message imprint, signed time, signature, signer certificate reference and certificate chain and can compare the imprint with the digest recorded in the proof bundle.",
          "A valid RFC 3161 structure is only one technical layer. Qualification under the EU eIDAS framework depends on the service being a qualified electronic time-stamping service provided by a qualified trust service provider and identified as qualified in the applicable EU Trusted List. A self-signed token, development certificate or sandbox service does not acquire qualified status merely because common cryptographic software accepts its signature.",
        ],
      },
      {
        heading: "What the eIDAS presumption covers",
        paragraphs: [
          "Article 41 of Regulation (EU) No 910/2014, as amended, gives a qualified electronic timestamp a presumption of the accuracy of the date and time it indicates and the integrity of the data to which that time is bound. A qualified timestamp issued in one Member State is recognised as qualified in the other Member States. The presumption concerns time and data integrity; it does not certify that a photograph depicts a true event, identify every person shown or prove that a scene was not staged.",
          "The distinction matters in construction disputes. A qualified token can strengthen the proposition that exact data existed by the indicated time and was not changed undetectably afterwards. Other questions remain subject to ordinary evidence: who controlled the device, whether the recorded location was authentic, whether the camera saw a physical scene, whether the work complied with a contract and what legal weight a tribunal gives the complete evidentiary record.",
        ],
      },
      {
        heading: "Provider status must be checked, not assumed",
        paragraphs: [
          "EU Member States publish trusted lists describing qualified trust service providers and the qualified services for which they are supervised. Provider identity alone is not enough: the specific service and its status at the relevant time matter. A production implementation therefore needs a documented trust policy that connects the token, signer certificate, service identity, trusted-list status and validation time instead of relying on a brand name or a generic TLS connection.",
          "Long-term validation also requires attention to certificate expiry, revocation information, algorithm strength and preservation of the material needed for later verification. SiteSealed's whitepaper targets durable proofs that outlive the vendor. Reaching that target requires more than obtaining a response from an API; it requires preserving the signed token and its validation context and making the result exportable to the party that may later challenge it.",
        ],
      },
      {
        heading: "What SiteSealed validates in the alpha",
        paragraphs: [
          "The active Rail A integration uses Evidency Sandbox. SiteSealed submits only a SHA-256 evidence digest, checks that the returned token binds the same digest, validates the CMS signature and ESSCertIDv2 signer binding, and verifies the certificate path to a sandbox root pinned in the release. These controls detect malformed, substituted or cryptographically invalid responses and keep the operational status from turning green merely because an HTTP request succeeded.",
          "None of those checks converts the sandbox service into a qualified production service. The current token is labelled test-only and not qualified, and it has no qualified eIDAS legal effect. Production qualification, a production trust policy and certificate revocation validation remain explicit gates. The public Ethereum anchor is a separate neutral rail and does not substitute for the statutory presumption of a genuinely qualified timestamp.",
        ],
      },
      {
        heading: "How to read the Evidence Report",
        paragraphs: [
          "The Evidence Report identifies the timestamp environment, token state and independent verification results. A sandbox-issued token should be read as evidence that the alpha integration produced and validated a particular test artefact, not as a qualified legal act. The report keeps the ALPHA and NOT QUALIFIED language visible even when the cryptographic checks pass.",
          "The same report separately describes the Ethereum anchor and the record's honest scope. This separation lets an expert agree that a signature, digest or Merkle proof is valid without being forced to accept a broader claim about legal qualification, authorship, sensor origin or factual truth. SiteSealed's design is strongest when each conclusion is no wider than the material that supports it.",
        ],
      },
    ],
    references: [
      {
        href: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02014R0910-20241018",
        label: "Read the consolidated eIDAS Regulation on EUR-Lex",
      },
      {
        href: "https://digital-strategy.ec.europa.eu/en/policies/eu-trusted-lists",
        label: "Consult the European Commission's EU Trusted Lists information",
      },
    ],
  },
  {
    slug: "verify",
    path: "/verify",
    changefreq: "monthly",
    priority: "0.9",
    title: "Verify a SiteSealed Record | Independent Evidence Checking",
    description: "Verify a SiteSealed construction record without an account by checking its exact-file hash, timestamp token and Ethereum Merkle inclusion proof.",
    h1: "How any party verifies a SiteSealed record without an account",
    lede: "Verification is designed for the opposing party, expert, lawyer or arbitrator, not only for the person who created the record. Public lookup is free, while the exported Evidence Report carries the source material needed for independent checking.",
    sections: [
      {
        heading: "Start with the record identifier and the exact original",
        paragraphs: [
          "A public SiteSealed record is addressed by its record identifier. Entering that identifier in the verification interface retrieves the public receipt and proof bundle; it does not disclose the private Recovery Kit or decrypt private storage. The canonical Evidence Report contains the visible original and embeds the exact original as an attachment, so a recipient can work from the same bytes that were sealed rather than from a screenshot or recompressed copy.",
          "Recalculate SHA-256 over the exact file and compare the result with the recorded file digest. If one byte differs, the digest differs and the file-integrity check fails. For a live web capture, the report also carries the canonical capture manifest and distinguishes client-reported location and time from hardware-attested facts. For an imported file, original capture time, place, author and sensor origin remain expressly unverified.",
        ],
      },
      {
        heading: "Recompute the evidence record and inspect its scope",
        paragraphs: [
          "The proof bundle contains the stable fields used to derive the evidence digest. Independent verification reconstructs the canonical representation and checks that its SHA-256 result matches the digest presented to the external rails. This catches a receipt whose fields were reordered incorrectly, substituted or altered after sealing. The report also identifies the schema and protocol versions required to interpret those fields.",
          "A successful digest calculation answers a narrow question: the exported data is internally consistent with the committed fingerprint. It does not prove that every client-supplied statement is true. Read the scope section before reading status colours. It separates cryptographically proven identity and integrity, server-bound context, browser-reported claims and facts for which the system has no attestation.",
        ],
      },
      {
        heading: "Validate the RFC 3161 token as the rail it actually is",
        paragraphs: [
          "When a timestamp token is attached, compare its message imprint with the SiteSealed evidence digest, validate the CMS signature, confirm the signer binding and build the certificate path under the stated trust policy. Preserve the complete token rather than a provider dashboard screenshot. These checks can be performed with standard cryptographic tooling and do not require access to SiteSealed's database.",
          "The current Evidency response comes from a sandbox. Even when its signature and pinned sandbox chain validate, it remains test-only, not qualified and without qualified eIDAS legal effect. An independent verifier must retain that qualification status in the conclusion. A future production token would additionally require the production provider and service to be qualified under the applicable EU Trusted List and the production validation policy to pass.",
        ],
      },
      {
        heading: "Verify the Ethereum anchor from any independent node",
        paragraphs: [
          "Fetch the full transaction by its 66-character hash from any Ethereum mainnet node. Confirm the chain ID, sender, recipient, block and finalized receipt. Decode the transaction calldata as the ASCII domain marker SSLD, followed by the protocol version byte and the 32-byte Merkle root. Compare that root byte-for-byte with the root printed in the Evidence Report; do not rely on a shortened explorer label.",
          "Next start with the record's leaf hash and follow every inclusion-path entry in order. Each entry states whether the sibling belongs on the left or right before hashing the pair under the declared Merkle protocol. The final value must equal the root committed in the transaction. This proves that the record leaf was included in the anchored batch without revealing sibling records. It does not prove the truth of the original content.",
        ],
      },
      {
        heading: "Record failures as carefully as successes",
        paragraphs: [
          "A missing token, pending transaction, invalid signature, mismatched digest or incomplete path is not a cosmetic warning. It changes the proof state and must remain visible. SiteSealed therefore keeps NOT ANCHORED, sandbox, ALPHA and NOT QUALIFIED wording instead of collapsing partially complete rails into a single reassuring badge. Verification should report each rail independently and state which checks were not possible.",
          "The result is portable by design. If SiteSealed disappeared, the exact original, receipt, timestamp token, Ethereum transaction data and Merkle path should still permit reconstruction with open tooling and public infrastructure. That is the practical meaning of proof over storage and verification by the adversary: the evidence does not become true because SiteSealed says so, and it does not become unverifiable because the portal is unavailable.",
        ],
      },
    ],
  },
]);

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function generatedBlock(name, body) {
  return `<!-- ${name}_START -->\n${body}\n    <!-- ${name}_END -->`;
}

function replaceGeneratedBlock(source, name, body) {
  const pattern = new RegExp(
    `<!-- ${name}_START -->[\\s\\S]*?<!-- ${name}_END -->`,
  );
  if (!pattern.test(source)) {
    throw new Error(`Missing ${name} markers in client/index.html.`);
  }
  return source.replace(pattern, generatedBlock(name, body));
}

function jsonForHtml(value) {
  return JSON.stringify(value, null, 2).replaceAll("<", "\\u003c");
}

function jsonLdScript(id, value) {
  const json = jsonForHtml(value)
    .split("\n")
    .map((line) => `      ${line}`)
    .join("\n");
  return `    <script type="application/ld+json" nonce="__SITESEALED_CSP_NONCE__" data-sitesealed-jsonld="${id}">\n${json}\n    </script>`;
}

function hreflangMarkup() {
  const links = SUPPORTED_LOCALES.map(
    (locale) =>
      `    <link rel="alternate" hreflang="${locale}" href="${origin}/?lang=${locale}" />`,
  );
  links.push(
    `    <link rel="alternate" hreflang="x-default" href="${origin}/" />`,
  );
  return links.join("\n");
}

function openGraphLocaleMarkup() {
  return SUPPORTED_LOCALES.map((locale, index) => {
    const property = index === 0 ? "og:locale" : "og:locale:alternate";
    return `    <meta property="${property}" content="${locale.replace("-", "_")}" />`;
  }).join("\n");
}

function structuredDataMarkup() {
  const software = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: "SiteSealed",
    description:
      "A web application for creating privacy-preserving construction evidence records, exporting one canonical Evidence Report and independently checking exact-file, RFC 3161 sandbox and Ethereum Merkle proof artefacts. The current sandbox timestamp is test-only and not qualified.",
    applicationCategory: "BusinessApplication",
    operatingSystem: "Web",
    url: `${origin}/`,
    image: socialImage,
    inLanguage: [...SUPPORTED_LOCALES],
    publisher: {
      "@type": "Organization",
      name: "SiteSealed",
      address: {
        "@type": "PostalAddress",
        addressLocality: "Sprimont",
        addressCountry: "BE",
      },
    },
  };
  const faq = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: [
      {
        "@type": "Question",
        name: "What does a sealed construction record prove?",
        acceptedAnswer: {
          "@type": "Answer",
          text: "It binds the exact original and canonical manifest to SHA-256 digests and exposes the state of each external proof rail. A valid digest and finalized Merkle anchor support integrity and inclusion conclusions. They do not prove that the depicted event is factually true.",
        },
      },
      {
        "@type": "Question",
        name: "What is a qualified eIDAS electronic timestamp?",
        acceptedAnswer: {
          "@type": "Answer",
          text: "It is a timestamp delivered as a qualified service by a qualified trust service provider under eIDAS. It carries a presumption concerning the accuracy of its date and time and the integrity of the bound data. SiteSealed currently uses Evidency Sandbox: its tokens are test-only, not qualified and have no qualified eIDAS legal effect.",
        },
      },
      {
        "@type": "Question",
        name: "How is the public-chain anchor verified?",
        acceptedAnswer: {
          "@type": "Answer",
          text: "Fetch the full Ethereum mainnet transaction from any node, decode its calldata as the ASCII marker SSLD plus a version byte and 32-byte Merkle root, recompute the root from the record leaf and every left or right inclusion-path sibling, and compare the two roots.",
        },
      },
      {
        "@type": "Question",
        name: "What does SiteSealed not prove?",
        acceptedAnswer: {
          "@type": "Answer",
          text: "It does not by itself prove truthfulness, that a scene was unstaged, physical sensor origin, hardware-attested location or authorship beyond the bound account. For imported files it does not prove the original capture time, place or author.",
        },
      },
    ],
  };
  return [jsonLdScript("software-application", software), jsonLdScript("faq", faq)].join("\n");
}

function publicNavigation() {
  return `
          <a href="/how-it-works">How SiteSealed works</a>
          <a href="/qualified-timestamping">Qualified timestamping explained</a>
          <a href="/verify">Independent record verification</a>`;
}

function renderPublicPage(page) {
  const sections = page.sections.map((section) => `
        <section class="public-page__section">
          <h2>${escapeHtml(section.heading)}</h2>
${section.paragraphs.map((paragraph) => `          <p>${escapeHtml(paragraph)}</p>`).join("\n")}
        </section>`).join("\n");
  const references = page.references?.length
    ? `
        <section class="public-page__section public-page__references">
          <h2>Authoritative references</h2>
          <ul>
${page.references.map((reference) => `            <li><a href="${escapeHtml(reference.href)}">${escapeHtml(reference.label)}</a></li>`).join("\n")}
          </ul>
        </section>`
    : "";

  return `<!doctype html>
<html lang="${DEFAULT_LOCALE}">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="theme-color" content="#061A2B" />
    <meta name="sitesealed-csp-nonce" content="__SITESEALED_CSP_NONCE__" />
    <meta name="description" content="${escapeHtml(page.description)}" />
    <meta name="robots" content="index, follow" />
    <link rel="canonical" href="${origin}${page.path}" />
    <meta property="og:type" content="article" />
    <meta property="og:site_name" content="SiteSealed" />
    <meta property="og:url" content="${origin}${page.path}" />
    <meta property="og:locale" content="en_US" />
    <meta property="og:title" content="${escapeHtml(page.title)}" />
    <meta property="og:description" content="${escapeHtml(page.description)}" />
    <meta property="og:image" content="${socialImage}" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${escapeHtml(page.title)}" />
    <meta name="twitter:description" content="${escapeHtml(page.description)}" />
    <meta name="twitter:image" content="${socialImage}" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg?v=20260812" />
    <link rel="stylesheet" href="/public-page.css" />
    <title>${escapeHtml(page.title)}</title>
  </head>
  <body class="public-page">
    <a class="public-page__skip" href="#main-content">Skip to the main content</a>
    <header class="public-page__header">
      <a class="public-page__brand" href="/" aria-label="SiteSealed home">
        <img src="/icon-192.svg?v=20260812" alt="" width="42" height="42" />
        <span>SITESEALED</span>
      </a>
      <nav aria-label="Public information pages">${publicNavigation()}
      </nav>
    </header>
    <main class="public-page__main" id="main-content">
      <div class="public-page__eyebrow">PUBLIC EXPLAINER / ALPHA HONEST SCOPE</div>
      <h1>${escapeHtml(page.h1)}</h1>
      <p class="public-page__lede">${escapeHtml(page.lede)}</p>
      <aside class="public-page__boundary" aria-label="Current qualification boundary">
        <strong>CURRENT BOUNDARY</strong>
        <p>Evidency Sandbox tokens are test-only, not qualified and have no qualified eIDAS legal effect. The current web capture class does not provide hardware camera, device, GNSS or clock attestation.</p>
      </aside>
${sections}${references}
      <section class="public-page__section public-page__next">
        <h2>Continue with the complete verification model</h2>
        <nav aria-label="Related SiteSealed explanations">${publicNavigation()}
          <a href="/#verify">Open the public record verifier</a>
          <a href="/documents/SiteSealed_Whitepaper_v1.0_Genesis.pdf">Read the founding whitepaper</a>
        </nav>
      </section>
    </main>
    <footer class="public-page__footer">
      <p><strong>SiteSealed</strong> — Sprimont, Belgium</p>
      <nav aria-label="Footer links">
        <a href="/">Return to the SiteSealed application</a>
        <a href="/documents/SiteSealed_EvidenceReport_SPECIMEN.pdf">Open the Evidence Report specimen</a>
      </nav>
      <p>Integrity and inclusion proofs do not establish the factual truth of the recorded content.</p>
    </footer>
  </body>
</html>
`;
}

function sitemapXml() {
  const urls = [
    { path: "/", changefreq: "monthly", priority: "1.0" },
    ...publicPages,
  ];
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((entry) => `  <url>
    <loc>${origin}${entry.path}</loc>
    <changefreq>${entry.changefreq}</changefreq>
    <priority>${entry.priority}</priority>
  </url>`).join("\n")}
</urlset>
`;
}

function assertCanonicalLocales() {
  const canonical = Intl.getCanonicalLocales(SUPPORTED_LOCALES);
  if (
    canonical.length !== SUPPORTED_LOCALES.length ||
    canonical.some((locale, index) => locale !== SUPPORTED_LOCALES[index])
  ) {
    throw new Error(
      `SUPPORTED_LOCALES contains a non-canonical BCP 47 tag: ${SUPPORTED_LOCALES.join(", ")}`,
    );
  }
}

async function generateIndexAndSitemap() {
  const indexPath = path.join(clientDirectory, "index.html");
  let index = await readFile(indexPath, "utf8");
  index = replaceGeneratedBlock(index, "SITESEALED_HREFLANG", hreflangMarkup());
  index = replaceGeneratedBlock(index, "SITESEALED_OG_LOCALES", openGraphLocaleMarkup());
  index = replaceGeneratedBlock(index, "SITESEALED_JSONLD", structuredDataMarkup());
  await writeFile(indexPath, index, "utf8");
  await writeFile(path.join(publicDirectory, "sitemap.xml"), sitemapXml(), "utf8");
}

async function generateDistributionPages() {
  const targetDirectory = path.join(distributionDirectory, ".public-pages");
  await mkdir(targetDirectory, { recursive: true });
  await Promise.all(
    publicPages.map((page) =>
      writeFile(
        path.join(targetDirectory, `${page.slug}.html`),
        renderPublicPage(page),
        "utf8",
      ),
    ),
  );
}

assertCanonicalLocales();
await generateIndexAndSitemap();
if (process.argv.includes("--dist")) await generateDistributionPages();

