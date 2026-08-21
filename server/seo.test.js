import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  LOCALE_OPTIONS,
  SUPPORTED_LOCALES,
} from "../client/src/i18n/index.js";
import { createApp } from "./server.js";

const projectDirectory = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const clientDirectory = path.join(projectDirectory, "client");
const distributionDirectory = path.join(clientDirectory, "dist");
const publicRoutes = ["/how-it-works", "/qualified-timestamping", "/verify"];

let server;
let baseUrl;

async function listen(app) {
  return new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
}

function attributes(source) {
  return Object.fromEntries(
    [...source.matchAll(/([:\w-]+)="([^"]*)"/g)].map((match) => [
      match[1],
      match[2],
    ]),
  );
}

function elements(html, tagName) {
  return [...html.matchAll(new RegExp(`<${tagName}\\b([^>]*)>`, "gi"))]
    .map((match) => attributes(match[1]));
}

function jsonLdBlocks(html) {
  return [...html.matchAll(
    /<script\b([^>]*)type="application\/ld\+json"([^>]*)>([\s\S]*?)<\/script>/gi,
  )].map((match) => ({
    attributes: attributes(`${match[1]} ${match[2]}`),
    value: JSON.parse(match[3]),
  }));
}

function assertWellFormedXml(xml) {
  const stack = [];
  const withoutComments = xml
    .replace(/<\?xml[\s\S]*?\?>/g, "")
    .replace(/<!--[\s\S]*?-->/g, "");
  for (const match of withoutComments.matchAll(/<\/?([A-Za-z_:][\w:.-]*)\b[^>]*>/g)) {
    const token = match[0];
    const name = match[1];
    if (token.startsWith("</")) {
      assert.equal(stack.pop(), name, `XML closes ${name} out of order`);
    } else if (!token.endsWith("/>")) {
      stack.push(name);
    }
  }
  assert.deepEqual(stack, [], "XML contains unclosed elements");
}

function visibleWordCount(html) {
  const text = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&[A-Za-z0-9#]+;/g, " ");
  return (text.match(/[\p{L}\p{N}][\p{L}\p{N}'’-]*/gu) ?? []).length;
}

function assertHeadingHierarchy(html, label) {
  const headings = [...html.matchAll(/<(h[1-3])\b[^>]*>/gi)]
    .map((match) => Number(match[1].slice(1)));
  assert.equal(headings.filter((level) => level === 1).length, 1, `${label} needs one h1`);
  assert.equal(headings[0], 1, `${label} must begin its heading hierarchy with h1`);
  let previous = 1;
  for (const level of headings.slice(1)) {
    assert.ok(level <= previous + 1, `${label} skips a heading level`);
    previous = level;
  }
}

function scrubNonce(html) {
  const nonce = html.match(
    /name="sitesealed-csp-nonce" content="([A-Za-z0-9_-]+)"/,
  )?.[1];
  assert.ok(nonce, "server HTML must contain a generated CSP nonce");
  return html.replaceAll(nonce, "TEST_CSP_NONCE");
}

before(async () => {
  server = await listen(createApp());
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
});

test("locale flags are complete assets and use the canonical eight-locale list", async () => {
  assert.deepEqual(
    LOCALE_OPTIONS.map((option) => option.locale),
    SUPPORTED_LOCALES,
  );
  for (const option of LOCALE_OPTIONS) {
    assert.match(option.flag, /^\/flags\/[a-z]{2}\.svg$/);
    const source = await readFile(
      path.join(distributionDirectory, option.flag.slice(1)),
      "utf8",
    );
    assert.match(source, /^<svg\b/);
    assert.match(source, /aria-label="[^"]+ flag"/);
  }
});

test("robots and sitemap expose only real public application URLs", async () => {
  const [robots, sitemap] = await Promise.all([
    readFile(path.join(distributionDirectory, "robots.txt"), "utf8"),
    readFile(path.join(distributionDirectory, "sitemap.xml"), "utf8"),
  ]);
  assert.equal(
    robots,
    "User-agent: *\nAllow: /\n\nSitemap: https://app.sitesealed.com/sitemap.xml\n",
  );
  assertWellFormedXml(sitemap);
  assert.doesNotMatch(sitemap, /<lastmod>/);
  const locations = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)]
    .map((match) => match[1]);
  assert.deepEqual(locations, [
    "https://app.sitesealed.com/",
    "https://app.sitesealed.com/how-it-works",
    "https://app.sitesealed.com/qualified-timestamping",
    "https://app.sitesealed.com/verify",
  ]);
  assert.doesNotMatch(sitemap, /\/api\/|\/verify\/[^<]+/);
  for (const location of locations) {
    const url = new URL(location);
    const response = await fetch(`${baseUrl}${url.pathname}${url.search}`);
    assert.equal(response.status, 200, `${location} must resolve`);
  }
});

test("root JSON-LD is parseable, nonce-compatible and honestly scoped", async () => {
  const response = await fetch(`${baseUrl}/`);
  const html = await response.text();
  const nonce = html.match(
    /name="sitesealed-csp-nonce" content="([A-Za-z0-9_-]+)"/,
  )?.[1];
  assert.ok(nonce);
  const blocks = jsonLdBlocks(html);
  assert.equal(blocks.length, 2);
  assert.ok(blocks.every((block) => block.attributes.nonce === nonce));

  const software = blocks.find((block) => block.value["@type"] === "SoftwareApplication")?.value;
  const faq = blocks.find((block) => block.value["@type"] === "FAQPage")?.value;
  assert.ok(software);
  assert.ok(faq);
  assert.deepEqual(software.inLanguage, SUPPORTED_LOCALES);
  assert.equal(software.applicationCategory, "BusinessApplication");
  assert.equal(software.operatingSystem, "Web");
  assert.equal(software.publisher.address.addressLocality, "Sprimont");
  assert.equal(software.publisher.address.addressCountry, "BE");
  assert.equal(faq.mainEntity.length, 4);
  assert.match(JSON.stringify(faq), /sandbox[^.]*test-only[^.]*not qualified/i);
  assert.doesNotMatch(JSON.stringify(blocks), /aggregateRating|reviewCount|price/i);
  const csp = response.headers.get("content-security-policy") ?? "";
  assert.match(csp, new RegExp(`script-src[^;]*'nonce-${nonce}'`));
  assert.doesNotMatch(csp, /unsafe-inline/);
});

test("hreflang is reciprocal for all eight canonical BCP 47 locales", async () => {
  assert.deepEqual(Intl.getCanonicalLocales(SUPPORTED_LOCALES), SUPPORTED_LOCALES);
  const expected = new Map([
    ...SUPPORTED_LOCALES.map((locale) => [
      locale,
      `https://app.sitesealed.com/?lang=${locale}`,
    ]),
    ["x-default", "https://app.sitesealed.com/"],
  ]);
  let referenceHtml = null;
  for (const locale of SUPPORTED_LOCALES) {
    const response = await fetch(`${baseUrl}/?lang=${locale}`);
    assert.equal(response.status, 200);
    const html = await response.text();
    const alternates = new Map(
      elements(html, "link")
        .filter((link) => link.rel === "alternate" && link.hreflang)
        .map((link) => [link.hreflang, link.href]),
    );
    assert.deepEqual(alternates, expected);
    const normalized = scrubNonce(html);
    referenceHtml ??= normalized;
    assert.equal(normalized, referenceHtml, `${locale} must receive the same app shell`);
  }
  for (const href of expected.values()) {
    const url = new URL(href);
    const response = await fetch(`${baseUrl}${url.pathname}${url.search}`);
    assert.equal(response.status, 200, `${href} must resolve`);
  }
});

test("the initial root response and every public page have crawlable semantics", async () => {
  const rootResponse = await fetch(`${baseUrl}/`);
  const rootHtml = await rootResponse.text();
  assertHeadingHierarchy(rootHtml, "root HTML");
  assert.match(
    rootHtml,
    /<h1[^>]*>Construction records that can verify themselves\.<\/h1>/,
  );
  assert.match(rootHtml, /<script type="module"[^>]*><\/script>/);

  for (const route of publicRoutes) {
    const response = await fetch(`${baseUrl}${route}`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type") ?? "", /text\/html/);
    const html = await response.text();
    assertHeadingHierarchy(html, route);
    assert.ok(visibleWordCount(html) >= 400, `${route} needs at least 400 words`);
    assert.match(html, new RegExp(`<link rel="canonical" href="https://app\\.sitesealed\\.com${route}"`));
    assert.equal(elements(html, "meta").filter((meta) => meta.name === "description").length, 1);
    assert.equal((html.match(/<title>[^<]+<\/title>/g) ?? []).length, 1);
    assert.doesNotMatch(html, />\s*(click here|read more|learn more)\s*</i);
    for (const image of elements(html, "img")) {
      assert.ok(Object.hasOwn(image, "alt"), `${route} contains an image without alt`);
    }
    for (const linkedRoute of publicRoutes) {
      assert.match(html, new RegExp(`href="${linkedRoute}"`));
    }
  }
});

test("the build contains every generated SEO artefact", async () => {
  const index = await readFile(path.join(distributionDirectory, "index.html"), "utf8");
  assert.equal(jsonLdBlocks(index).length, 2);
  assert.equal(elements(index, "link").filter((link) => link.hreflang).length, 9);
  await Promise.all([
    readFile(path.join(distributionDirectory, "robots.txt")),
    readFile(path.join(distributionDirectory, "sitemap.xml")),
    readFile(path.join(distributionDirectory, "public-page.css")),
    ...publicRoutes.map((route) =>
      readFile(
        path.join(distributionDirectory, ".public-pages", `${route.slice(1)}.html`),
      ),
    ),
  ]);
});

