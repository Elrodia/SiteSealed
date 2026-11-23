// Serialized into the head of the isolated static site. No shared application imports.
export function startMarketing({ origin, cbid, mode, paths }) {
  if (!(mode === "google" || (mode === "cookiebot" && cbid)) || location.origin !== origin || window.top !== window.self ||
      !paths.includes(location.pathname) || location.search || location.hash) return;

  const template = document.getElementById("advertising-code");
  const nonce = document.currentScript?.nonce;
  if (!nonce) return;
  let listening = false;
  let live = false;
  function loadGoogle() {
    const script = document.createElement("script");
    if (nonce) script.nonce = nonce;
    script.async = true;
    script.crossOrigin = "anonymous";
    script.referrerPolicy = "strict-origin";
    script.src = template.content.querySelector("script").src;
    document.head.append(script);
  }
  function subscribe() {
    if (listening || typeof window.__tcfapi !== "function") return;
    listening = true;
    window.__tcfapi("addEventListener", 2, (data, ok) => {
      // Wait while the visitor is editing. Only a settled, affirmative TCF
      // decision qualifies; do not treat "outside EEA" as implicit consent.
      if (ok && data?.eventStatus === "cmpuishown") return;
      const allowed = ok === true && data?.cmpStatus === "loaded" && data.cmpId === (mode === "google" ? 300 : 134) &&
        ["tcloaded", "useractioncomplete"].includes(data.eventStatus) &&
        typeof data.tcString === "string" && data.tcString.length > 0 &&
        data.vendor?.consents?.[755] === true && // Google Advertising Products
        [1, 3, 4].every(purpose => data.purpose?.consents?.[purpose] === true);
      if (!allowed) {
        if (mode === "google") window.adsbygoogle.pauseAdRequests = 1;
        // Removing a <script> does not unload it. Start a fresh document.
        if (live) { live = false; location.reload(); }
        return;
      }
      if (live) return;
      live = true;
      if (mode === "google") window.adsbygoogle.pauseAdRequests = 0;
      else loadGoogle();
    });
  }
  document.addEventListener("click", event => {
    if (!event.target.closest?.("[data-ad-privacy]")) return;
    if (mode === "google") window.googlefc?.showRevocationMessage?.();
    else window.Cookiebot?.renew();
  });
  if (mode === "google") {
    (window.adsbygoogle ||= []).pauseAdRequests = 1;
    const fc = window.googlefc ||= {};
    (fc.callbackQueue ||= []).push({ CONSENT_API_READY: subscribe });
    loadGoogle(); // Needed for Google's own consent UI. Requests for ads remain paused.
    return;
  }
  const cmp = document.createElement("script");
  if (nonce) cmp.nonce = nonce;
  cmp.id = "Cookiebot";
  cmp.async = true;
  cmp.dataset.cbid = cbid;
  cmp.dataset.framework = "TCF";
  cmp.src = "https://consent.cookiebot.com/uc.js";
  cmp.onload = subscribe;
  window.addEventListener("CookiebotOnConsentReady", subscribe);
  document.head.append(cmp);
}
