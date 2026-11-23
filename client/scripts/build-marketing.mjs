import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { publicPages, renderPublicPage } from "./generate-public-seo.mjs";
import { startMarketing } from "./marketing-consent.mjs";
import { publicGuidesOrigin } from "../../server/marketing-links.js";

const client = fileURLToPath(new URL("../", import.meta.url));
const app = "https://app.sitesealed.com";
const account = "ca-pub-3852727861047545";
const attr = s => s.replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;");
const templates = await readFile(path.join(client, "index.html"), "utf8");

export async function buildMarketing({ origin, cbid = "", mode = "off", target = path.join(client, "dist-marketing") }) {
  if (!origin) throw new Error("Set SITESEALED_MARKETING_ORIGIN to a dedicated, public-only HTTPS origin.");
  publicGuidesOrigin(origin, process.env.PUBLIC_BASE_URL);
  if (cbid && !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(cbid))
    throw new Error("SITESEALED_COOKIEBOT_ID must be the actual Cookiebot domain-group UUID.");
  if (!["off","google","cookiebot"].includes(mode) || (mode === "cookiebot" && !cbid))
    throw new Error("SITESEALED_CMP must be off, google, or cookiebot (with SITESEALED_COOKIEBOT_ID).");

  const paths = ["/", ...publicPages.flatMap(p => [p.path, p.path + "/"])];
  const inline = "(" + startMarketing.toString() + ")(" + JSON.stringify({ origin, cbid, mode, paths }) + ");";
  // Source files remain inert on a bare file host. The dedicated service
  // opts in per HTTP response with a fresh nonce, never a reusable build nonce.
  const csp = "script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'";
  const head = `<meta http-equiv="Content-Security-Policy" content="${attr(csp)}">
    <meta name="referrer" content="strict-origin">
    <meta name="google-adsense-account" content="${account}">
    <template id="advertising-code"><script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${account}" crossorigin="anonymous"></script></template>
    <script>${inline}</script>`;
  const privacy = `<p>Advertising on these public guides is optional. If you consent, Google and its partners may use cookies and personal data to deliver ads. <a href="https://business.safety.google/privacy/">Google advertising privacy information</a>.</p>` +
    (mode !== "off" ? '<button type="button" data-ad-privacy>Change or withdraw advertising consent</button>' : "<p>Advertising is disabled.</p>");
  const hero = templates.match(/<main class="seo-shell"[^>]*>([\s\S]*?)<\/main>/)?.[1];
  if (!hero) throw new Error("Static homepage copy missing in client/index.html");
  const homepage = `<!doctype html><html lang="en-US"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Explore SiteSealed’s construction evidence pipeline and its current proof limits.">
    <link rel="icon" type="image/png" sizes="192x192" href="/favicon-192.png" />
    <link rel="canonical" href="${app}/"><link rel="stylesheet" href="/public-page.css">
    <title>SiteSealed | Construction evidence guides</title></head>
    <body class="public-page"><main class="public-page__main">${hero}</main><footer class="public-page__footer">
    <a href="${app}/">Open the SiteSealed application</a></footer></body></html>`;
  const results = [["", homepage], ...publicPages.map(p => [p.slug, renderPublicPage(p)])];
  for (const [slug, source] of results) {
    const page = source.replace(/\s*<meta name="sitesealed-csp-nonce"[^>]*\/>/, "")
      .replace(/\s*<meta name="google-adsense-account"[^>]*\/>/, "")
      .replace(/(<meta charset="[^"]+"\s*\/?>)/i, (_tag, charset) => charset + "\n" + head)
      .replace('href="/#verify"', 'href="' + app + '/#verify"')
      .replace('href="/">Return to the SiteSealed application', 'href="' + app + '/">Return to the SiteSealed application')
      .replace('href="/documents/SiteSealed_Whitepaper', 'href="' + app + '/documents/SiteSealed_Whitepaper')
      .replace(/\s*<a href="\/documents\/SiteSealed_EvidenceReport_SPECIMEN\.pdf"[^>]*>[^<]*<\/a>/g, "")
      .replace("</footer>", privacy + "</footer>");
    const dir = path.join(target, slug);
    await mkdir(dir, {recursive: true});
    await writeFile(path.join(dir, "index.html"), page);
  }
  for (const asset of ["favicon-192.png","favicon.ico","favicon.svg","icon-192.svg","public-page.css"])
    await copyFile(path.join(client, "public", asset), path.join(target, asset));
  await writeFile(path.join(target, "ads.txt"), "google.com, pub-3852727861047545, DIRECT, f08c47fec0942fa0\n");
  await writeFile(path.join(target, "robots.txt"), "User-agent: *\nAllow: /\n");
  await writeFile(path.join(target, ".deployment.json"), JSON.stringify({origin, csp}));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  await buildMarketing({ origin: process.env.SITESEALED_MARKETING_ORIGIN, cbid: process.env.SITESEALED_COOKIEBOT_ID, mode: process.env.SITESEALED_CMP });
