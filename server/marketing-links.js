// This is a navigation destination only. Never proxy or execute its code on
// the evidence origin, nor copy the current URL, query string or fragment.
export function publicGuidesOrigin(value, appOrigin) {
  if (!value) return "";
  const url = new URL(value);
  if (url.protocol !== "https:" || url.origin !== value || url.port ||
      !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(url.hostname) ||
      url.hostname === "app.sitesealed.com" ||
      (appOrigin && url.hostname === new URL(appOrigin).hostname)) {
    throw new Error("SITESEALED_MARKETING_ORIGIN must be a separate, bare HTTPS origin.");
  }
  return url.origin;
}

export function linkPublicGuides(html, origin) {
  if (!origin) return html;
  return html.replace('<div id="root">', `<div id="root" data-public-guides-origin="${origin}">`)
    .replace(/href="(\/(?:how-it-works|qualified-timestamping|verify))"/g,
      (_match, page) => `rel="noreferrer" href="${origin}${page}"`);
}
