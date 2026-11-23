import test from "node:test";
import assert from "node:assert/strict";
import { get as httpGet } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { runInNewContext } from "node:vm";
import { buildMarketing } from "../client/scripts/build-marketing.mjs";
import { makeMarketingServer } from "../client/scripts/serve-marketing.mjs";
import { startMarketing } from "../client/scripts/marketing-consent.mjs";
import { publicPages, renderPublicPage } from "../client/scripts/generate-public-seo.mjs";

const origin = "https://marketing.example.test";
const app = "https://app.sitesealed.com";
const cbid = "7ab925bd-d87e-4e8e-aa44-fe056b8f7f00"; // synthetic test value, never deployed
const scriptUrl = "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-3852727861047545";
const grant = {eventStatus:"useractioncomplete", cmpStatus:"loaded",cmpId:134,tcString:"synthetic",
  vendor:{consents:{755:true}},purpose:{consents:{1:true,3:true,4:true}}};
function simulate({cfg = {origin, cbid, mode:"cookiebot", paths:["/"]}, actualOrigin = origin, pathname = "/", search = "", hash = ""} = {}) {
  const scripts = [];
  let tc, clicks, reloads = 0, renews = 0;
  const win = {addEventListener(){}, googlefc:{showRevocationMessage(){renews++;}}, Cookiebot:{renew(){renews++;}}, __tcfapi(name, version, fn) {
    assert.equal(name,"addEventListener"); assert.equal(version,2); tc = fn;
  }};
  win.top = win.self = win;
  const location = {origin:actualOrigin,pathname,search,hash,reload(){ reloads++; }};
  const document = {currentScript:{nonce:"test-nonce"},head:{append:s=>scripts.push(s)},getElementById:()=>({content:{querySelector:()=>({src:scriptUrl})}}),
    createElement:()=>({dataset:{}}),addEventListener:(type,fn)=>{if(type==="click") clicks=fn;}};
  runInNewContext("(" + startMarketing.toString() + ")(cfg)", {cfg,window:win,location,document});
  scripts[0]?.onload?.();
  win.googlefc.callbackQueue?.forEach(c=>c.CONSENT_API_READY());
  return {scripts, win, event:(data,ok=true)=>tc(data,ok), reopen:()=>clicks({target:{closest:()=>true}}),
    reloads:()=>reloads, renews:()=>renews};
}

test("marketing never contacts Google before valid affirmative CMP consent, or when disabled/misplaced", () => {
  for (const options of [{cfg:{origin,paths:["/"]}},{actualOrigin:app},{pathname:"/records/test"},{search:"?id=secret"},{hash:"#verify"}]) {
    assert.deepEqual(simulate(options).scripts, []);
  }
  const visit = simulate();
  assert.deepEqual(visit.scripts.map(s=>s.src), ["https://consent.cookiebot.com/uc.js"]);
  for (const [patch,ok] of [[{},false],[{cmpId:2},true],[{tcString:""},true],[{eventStatus:"cmpuishown"},true],
    [{purpose:{consents:{1:true,3:true,4:false}}},true],[{vendor:{consents:{755:false}}},true]]) visit.event({...grant,...patch},ok);
  assert.equal(visit.scripts.length,1);
  visit.event(grant); visit.event(grant);
  const ad = visit.scripts[1];
  assert.equal(visit.scripts.length,2); assert.equal(ad.src,scriptUrl);
  assert.equal(ad.async,true); assert.equal(ad.crossOrigin,"anonymous");
  assert.equal(ad.nonce,"test-nonce"); assert.equal(visit.scripts[0].nonce,"test-nonce");
  visit.reopen(); assert.equal(visit.renews(),1);
  visit.event({...grant,vendor:{consents:{755:false}}}); assert.equal(visit.reloads(),1);
});

test("Google CMP bootstrap pauses ad requests before loading and resumes only after its own consent", () => {
  const cfg = {origin, mode:"google", paths:["/"]};
  assert.deepEqual(simulate({cfg,actualOrigin:app}).scripts, []);
  const visit = simulate({cfg});
  assert.equal(visit.scripts.length,1); assert.equal(visit.scripts[0].src,scriptUrl);
  assert.equal(visit.scripts[0].referrerPolicy,"strict-origin");
  assert.equal(visit.win.adsbygoogle.pauseAdRequests,1);
  visit.event(grant); assert.equal(visit.win.adsbygoogle.pauseAdRequests,1);
  visit.event({...grant,cmpId:300}); assert.equal(visit.win.adsbygoogle.pauseAdRequests,0);
  visit.reopen(); assert.equal(visit.renews(),1);
  visit.event({...grant,cmpId:300,tcString:""}); assert.equal(visit.win.adsbygoogle.pauseAdRequests,1);
  assert.equal(visit.reloads(),1);
});

test("isolated marketing service serves all four editorial heads; rejects aliases, private routes, and mismatched builds", async t => {
  const target = await mkdtemp(path.join(tmpdir(),"sitesealed-marketing-"));
  t.after(()=>rm(target,{recursive:true,force:true}));
  for (const value of [app,app + "/", "https://app.sitesealed.com.", "https://user@marketing.example.test", "http://marketing.example.test"])
    await assert.rejects(buildMarketing({origin:value,target}));
  await assert.rejects(buildMarketing({origin,cbid:"invalid",target}));
  await assert.rejects(buildMarketing({origin,mode:"cookiebot",target}));
  await buildMarketing({origin,mode:"google",target});
  await assert.rejects(makeMarketingServer({target,origin:"https://other.example.test"}));
  const server = await makeMarketingServer({target,origin});
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve)); t.after(()=>new Promise(resolve=>server.close(resolve)));
  const base = "http://127.0.0.1:" + server.address().port;
  const get = (url,host="marketing.example.test")=>new Promise((resolve,reject)=>{
    httpGet(base+url,{headers:{host,connection:"close"}}, async res=>{
      const chunks=[]; for await (const c of res) chunks.push(c);
      resolve(new Response(Buffer.concat(chunks),{status:res.statusCode,headers:res.headers}));
    }).on("error",reject);
  });
  for (const item of ["/", ...publicPages.map(p=>p.path)]) {
    const res = await get(item); assert.equal(res.status,200);
    const html = await res.text(), head = html.slice(0,html.indexOf("</head>"));
    assert.match(head, /<link\b(?=[^>]*\brel="icon")(?=[^>]*\bhref="\/favicon-192\.png")(?=[^>]*\btype="image\/png")(?=[^>]*\bsizes="192x192")[^>]*>/i, item);
    assert.equal((head.match(/name="google-adsense-account"/g)||[]).length,1);
    assert.ok(head.includes('<template id="advertising-code"><script async src="'+scriptUrl+'" crossorigin="anonymous"></script></template>'));
    assert.equal((html.match(/<h1\b/g)||[]).length,1); assert.match(html, /Change or withdraw advertising consent/);
    assert.doesNotMatch(html,/\/src\/main|\.jsx|SPECIMEN\.pdf|__SITESEALED_CSP_NONCE__|type="module"/);
    const [,nonce] = head.match(/<script nonce="([^"]+)">/);
    assert.ok(res.headers.get("content-security-policy").includes("'nonce-" + nonce + "'"));
    assert.notEqual(res.headers.get("content-security-policy"),(await get(item)).headers.get("content-security-policy"));
    assert.doesNotMatch(res.headers.get("content-security-policy"), /unsafe-(eval|inline)/);
    assert.equal(res.headers.get("set-cookie"),null);
  }
  for (const p of ["/api/auth/session","/record/example","/verify/recordId","/.deployment.json","/unknown","/documents/specimen.pdf"]) {
    const res = await get(p); assert.equal(res.status,404); assert.doesNotMatch(await res.text(),/adsbygoogle/);
  }
  assert.equal((await get("/", "app.sitesealed.com")).status,421);
  assert.equal((await get("/ads.txt")).status,200);
  assert.equal((await get("/healthz")).status,200);
  for (const [name, mime] of [["favicon-192.png", /^image\/png(?:;|$)/], ["favicon.ico", /^image\/(?:x-icon|vnd\.microsoft\.icon)(?:;|$)/]]) {
    const res = await get("/" + name);
    assert.equal(res.status, 200, name);
    assert.match(res.headers.get("content-type") ?? "", mime);
    assert.deepEqual(Buffer.from(await res.arrayBuffer()), await readFile(new URL("../client/public/" + name, import.meta.url)));
  }

  const appIndex = await readFile(new URL("../client/index.html", import.meta.url), "utf8");
  for (const html of [appIndex,...publicPages.map(renderPublicPage)]) {
    assert.match(html,/google-adsense-account/);
    assert.doesNotMatch(html,/adsbygoogle\.js|consent\.cookiebot\.com/);
  }
});
