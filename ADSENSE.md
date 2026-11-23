# AdSense: separate public pages, optional activation

The AdSense publisher is `ca-pub-3852727861047545`. The existing evidence
application and its three public guides contain only Google's ownership meta
tag, which makes **no request**. Never put advertising JavaScript on the origin
where people sign in, capture or import files, recover keys, export PDFs, or
verify specific records. `crossorigin="anonymous"` is not a sandbox.

The optional public-only service serves **four** English editorial pages:
`/`, `/how-it-works`, `/qualified-timestamping`, and `/verify` (the guide,
not a record lookup). Each head contains the requested async script in an inert
template. At runtime the loader creates the actual script in the head. The
public copy is shared with the application; canonical links point to the
original editorial URLs to avoid competing copies. Application links navigate
to the original origin. There is no SPA fallback and no API or uploaded files.

## Deploy (separate service; no changes to Rails or the evidence web service)

1. Obtain an HTTPS host reserved exclusively for the public guides. Keep the
   app on `app.sitesealed.com` and the existing apex/www redirects intact. Do
   not reuse an alias that also serves the application. Keep the application's
   session/CSRF cookies host-only; do not share API credentials, domain-wide
   cookies, credentialed CORS or browser storage with the marketing service.
2. Use Node 22.13+ (supported versions per package.json). On the **new** service
   set `SITESEALED_MARKETING_ORIGIN` to the exact HTTPS origin, without a trailing
   slash, at both build and run time. Set `SITESEALED_CMP=off` first. Build with
   `npm run build:marketing --workspace client`, then start with
   `npm run start:marketing --workspace client`. No additional packages, worker,
   database, OAuth credentials or proof-rail secrets are needed. Only this
   service requires these commands; do not inherit the app's start command.
   It listens on the platform's `PORT` (default 3000); health check `/healthz`.
   Configure TLS at the host/proxy and preserve the public Host header.
3. In AdSense, add/verify the site's domain and request review (the ownership
   meta is already present). Set up **Auto ads**, its formats and exclusions.
   The marketing origin serves `/ads.txt`; follow Google's instructions for the
   owning root domain if it is a subdomain (do not replace someone else's
   ads.txt). Configure an accurate publisher privacy policy and its public URL
   before activation; the footer disclosure is not a complete privacy policy.
4. Choose one consent mode below, rebuild, and redeploy **only** the marketing
   service. Review and approval of the site, geographic eligibility, CMP
   configuration, blockers and the ad auction remain outside the code. No
   impressions, placements or revenue are guaranteed.

| Build-time setting | Behaviour |
| --- | --- |
| `SITESEALED_CMP=off` (default) | Neither CMP nor advertising scripts are downloaded. Use for verification, preview and rollback. |
| `SITESEALED_CMP=google` | Use Google's **Privacy & messaging → European regulations**. Select the site, privacy-policy URL and languages, turn on the one-click refusal option, and **publish** the message. No external CMP account or ID needed. The tag loads with ad requests already paused so Google can display the message. Google says its scripts may read existing Google cookies even when requests are paused. |
| `SITESEALED_CMP=cookiebot` | Optional if you already use Cookiebot: configure the dedicated public domain, IAB TCF, Google Advertising Products, opt-in/refusal, transparent vendor/purpose controls and privacy notice. Supply the real public Cookiebot domain-group UUID in `SITESEALED_COOKIEBOT_ID`. This mode does not download the AdSense script until affirmative consent. |

Only a settled TCF event from the configured CMP with a nonempty consent string,
Google vendor consent and affirmative purposes 1, 3 and 4 can start ads. Google
also applies its own requirements; this local gate does **not** certify legal
compliance. There is no implied consent from geography. No consent signal
(including when the CMP does not run in a region) means no ads. The footer
reopens the provider's consent controls; after withdrawal, ad requests are
paused in Google mode and the document reloads to discard running ad code.
Do not use both CMPs at once.

## Verify before activation

- Visit all four pages via the dedicated hostname, with fresh browser storage.
  Check that the consent choices actually appear for eligible traffic. Refuse
  and inspect the network: no ad-serving request. In Google mode the initial
  AdSense/CMP scripts themselves are **expected**; in Cookiebot mode the
  AdSense script itself must be absent until grant. Test acceptance, refusal on
  a later visit, revisiting consent, and a blocked/unavailable CMP.
- Check in DevTools that the served page has a fresh CSP nonce on each request
  and no `unsafe-inline` or `unsafe-eval` in its script policy. The host sends
  only the origin as cross-origin referrer. Do not strip or rewrite the CSP;
  Google's documented broader policy is more permissive, and some creatives
  may not work under ours. Do **not** weaken the evidence origin for ad fill.
- The generated HTML in `client/dist-marketing` without the dedicated server
  intentionally has a script-blocking CSP. Do not copy it over `client/dist`
  or serve it from Express. Unexpected Host, private routes, query strings,
  fragments and framed documents must not activate ads. Never send private
  record identifiers to the marketing site.
- `node --test server/adsense.test.js` tests the build, four heads, ownership
  meta, isolation and consent transitions without contacting ad vendors.

Official references: [Auto ads](https://support.google.com/adsense/answer/9261307),
[site verification](https://support.google.com/adsense/answer/7584263),
[certified CMPs](https://support.google.com/adsense/answer/13554116),
[publisher TCF integration](https://support.google.com/adsense/answer/9804260),
[before requesting ads](https://support.google.com/adsense/answer/7670312),
[Google EU consent messages](https://support.google.com/adsense/answer/10960768),
[Google revocation API](https://developers.google.com/funding-choices/fc-api-docs),
[strict CSP](https://support.google.com/adsense/answer/16283098) and
[Cookiebot TCF setup](https://support.cookiebot.com/hc/en-us/articles/360007652694).
