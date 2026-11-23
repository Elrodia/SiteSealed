import assert from "node:assert/strict";
import test from "node:test";
import { publicGuidesOrigin, linkPublicGuides } from "./marketing-links.js";
import { createApp } from "./server.js";

const origin = "https://guides.example.test";
test("public navigation accepts only an independent HTTPS origin", () => {
  assert.equal(publicGuidesOrigin(undefined), "");
  assert.equal(publicGuidesOrigin(origin), origin);
  for (const value of ["https://app.sitesealed.com", origin + "/private",
    origin + "?token=abc", 'https://example.test"x=y', "https://user@guides.example.test",
    "https://guides.example.test:3000", "http://guides.example.test", origin + "."])
    assert.throws(() => publicGuidesOrigin(value));
  assert.throws(() => publicGuidesOrigin(origin, origin));
  assert.equal(linkPublicGuides('<a href="/verify/record-id">', origin), '<a href="/verify/record-id">');
});

test("the app can link to the marketing service without allowing any ad or sending recovery URL data", async (t) => {
  const app = createApp({ marketingOrigin: origin });
  const server = await new Promise(resolve => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  for (const route of ["/?lang=fr-BE", "/verify/private-record?private=123", "/how-it-works"]) {
    const res = await fetch(base + route);
    const html = await res.text();
    assert.equal(res.status, 200);
    assert.ok(html.includes('rel="noreferrer" href="' + origin + '/how-it-works"'));
    assert.doesNotMatch(html, /private-record|private=123|adsbygoogle\.js|consent\.cookiebot\.com/);
    assert.doesNotMatch(res.headers.get("content-security-policy"), /googlesyndication|doubleclick|unsafe-inline|strict-dynamic/);
  }
});
