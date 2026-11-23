import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { publicPages } from "./generate-public-seo.mjs";

// Deliberately not a generic static file host. Never serve an application,
// API, user-controlled path, SPA fallback, private file or directory listing.
export async function makeMarketingServer({target = fileURLToPath(new URL("../dist-marketing/", import.meta.url)), origin} = {}) {
  const deploy = JSON.parse(await readFile(path.join(target, ".deployment.json"), "utf8"));
  if (!origin || deploy.origin !== origin || new URL(origin).hostname === "app.sitesealed.com")
    throw new Error("Marketing host must match its build-time isolated origin.");
  const host = new URL(origin).host;
  const pages = new Map([["/", "index.html"], ...publicPages.flatMap(({path: url, slug}) =>
    [[url, slug + "/index.html"], [url + "/", slug + "/index.html"]])]);
  const assets = new Map([["/public-page.css", "text/css"], ["/favicon.svg", "image/svg+xml"],
    ["/icon-192.svg", "image/svg+xml"], ["/robots.txt", "text/plain"], ["/ads.txt", "text/plain"]]);
  return createServer(async (req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    const end = (code, body) => { res.statusCode = code; res.end(body); };
    if (!["GET", "HEAD"].includes(req.method)) { res.setHeader("Allow", "GET, HEAD"); return end(405); }
    if (req.url === "/healthz") return end(200, "ok");
    if (req.headers.host?.toLowerCase() !== host) return end(421);
    const pathname = req.url.split("?")[0];
    const page = pages.get(pathname);
    const mime = assets.get(pathname);
    if (!page && !mime) return end(404, "Not found");
    try {
      let bytes = await readFile(path.join(target, page || pathname.slice(1)));
      if (page) {
        const nonce = randomBytes(24).toString("base64");
        const csp = `script-src 'nonce-${nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; form-action 'none'`;
        const html = bytes.toString();
        if (!html.includes(deploy.csp) || !html.includes("<script>")) return end(500, "Incomplete marketing build");
        bytes = Buffer.from(html.replace(deploy.csp, csp).replace("<script>", '<script nonce="' + nonce + '">'));
        res.setHeader("Content-Security-Policy", csp + "; frame-ancestors 'none'");
        res.setHeader("Cache-Control", "private, no-store");
      }
      res.setHeader("Content-Type", (mime || "text/html") + "; charset=utf-8");
      res.setHeader("Content-Length", bytes.length);
      end(200, req.method === "HEAD" ? undefined : bytes);
    } catch { end(500, "Build file unavailable"); }
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const server = await makeMarketingServer({origin: process.env.SITESEALED_MARKETING_ORIGIN});
  server.listen(Number(process.env.PORT || 3000), "0.0.0.0");
}
