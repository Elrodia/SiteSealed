import { baseMessages } from "./base.js";
import { deDE } from "./de-DE.js";
import { frBE } from "./fr-BE.js";
import { nlBE } from "./nl-BE.js";
import { ptBR } from "./pt-BR.js";

export const DEFAULT_LOCALE = "en-US";
export const SUPPORTED_LOCALES = Object.freeze([
  "en-US",
  "fr-BE",
  "nl-BE",
  "de-DE",
  "pt-BR",
]);

export const LOCALE_OPTIONS = Object.freeze([
  { locale: "en-US", label: "English (US)", shortLabel: "EN" },
  { locale: "fr-BE", label: "Français (Belgique)", shortLabel: "FR" },
  { locale: "nl-BE", label: "Nederlands (België)", shortLabel: "NL" },
  { locale: "de-DE", label: "Deutsch", shortLabel: "DE" },
  { locale: "pt-BR", label: "Português (Brasil)", shortLabel: "PT-BR" },
]);

export const catalogs = Object.freeze({
  "en-US": baseMessages,
  "fr-BE": frBE,
  "nl-BE": nlBE,
  "de-DE": deDE,
  "pt-BR": ptBR,
});

const localeByLanguage = Object.freeze({
  en: "en-US",
  fr: "fr-BE",
  nl: "nl-BE",
  de: "de-DE",
  pt: "pt-BR",
});

const googleLocales = Object.freeze({
  "en-US": "en_US",
  "fr-BE": "fr_FR",
  "nl-BE": "nl_NL",
  "de-DE": "de_DE",
  "pt-BR": "pt_BR",
});

let activeLocale = DEFAULT_LOCALE;

export function normalizeLocale(value) {
  const candidate = String(value ?? "").trim().replaceAll("_", "-");
  if (!candidate) return DEFAULT_LOCALE;
  const exact = SUPPORTED_LOCALES.find(
    (locale) => locale.toLowerCase() === candidate.toLowerCase(),
  );
  if (exact) return exact;
  return localeByLanguage[candidate.split("-")[0].toLowerCase()] ?? DEFAULT_LOCALE;
}

export function detectLocale({ search = "", stored = "", languages = [] } = {}) {
  const requested = new URLSearchParams(String(search).replace(/^\?/, "")).get("lang");
  if (requested) return normalizeLocale(requested);
  if (stored) return normalizeLocale(stored);
  for (const language of languages) {
    const normalized = normalizeLocale(language);
    if (normalized !== DEFAULT_LOCALE || String(language).toLowerCase().startsWith("en")) {
      return normalized;
    }
  }
  return DEFAULT_LOCALE;
}

export function setActiveLocale(locale) {
  activeLocale = normalizeLocale(locale);
  return activeLocale;
}

export function getActiveLocale() {
  return activeLocale;
}

function interpolate(message, variables = {}) {
  return String(message).replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g, (match, name) =>
    Object.hasOwn(variables, name) ? String(variables[name]) : match,
  );
}

export function translate(locale, id, variables) {
  const normalized = normalizeLocale(locale);
  const message = catalogs[normalized]?.[id] ?? baseMessages[id] ?? id;
  return interpolate(message, variables);
}

const exactSourceIds = new Map(
  Object.entries(baseMessages).map(([id, source]) => [source, id]),
);

const sourceAliases = new Map([
  ["Whitepaper", "nav.whitepaper"],
  ["Read the whitepaper", "landing.readWhitepaper"],
  ["Download the specimen", "landing.downloadSpecimen"],
  ["Whitepaper v1.0", "footer.whitepaper"],
  ["Evidence Report specimen", "footer.specimen"],
]);

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const sourceTemplates = Object.entries(baseMessages)
  .filter(([, source]) => /\{[A-Za-z][A-Za-z0-9]*\}/.test(source))
  .map(([id, source]) => {
    const names = [];
    const parts = source.split(/(\{[A-Za-z][A-Za-z0-9]*\})/g);
    const pattern = parts.map((part) => {
      const match = part.match(/^\{([A-Za-z][A-Za-z0-9]*)\}$/);
      if (!match) return escapeRegExp(part);
      names.push(match[1]);
      return "([\\s\\S]*?)";
    }).join("");
    return { id, names, regex: new RegExp(`^${pattern}$`) };
  })
  .sort((left, right) => baseMessages[right.id].length - baseMessages[left.id].length);

export function translateSource(locale, source) {
  if (typeof source !== "string" || !source) return source;
  const directId = exactSourceIds.get(source) ?? sourceAliases.get(source);
  if (directId) return translate(locale, directId);
  for (const template of sourceTemplates) {
    const match = source.match(template.regex);
    if (!match) continue;
    const variables = Object.fromEntries(
      template.names.map((name, index) => [name, match[index + 1]]),
    );
    return translate(locale, template.id, variables);
  }
  return source;
}

export function googleLocaleFor(locale) {
  return googleLocales[normalizeLocale(locale)] ?? googleLocales[DEFAULT_LOCALE];
}

export function formatDateTime(locale, value, options = {}) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.valueOf())) return translate(locale, "report.unavailable");
  return new Intl.DateTimeFormat(normalizeLocale(locale), {
    dateStyle: "medium",
    timeStyle: "medium",
    ...options,
  }).format(date);
}

export function formatNumber(locale, value, options = {}) {
  return new Intl.NumberFormat(normalizeLocale(locale), options).format(Number(value));
}

const byteUnits = Object.freeze({
  "en-US": ["B", "KB", "MB"],
  "fr-BE": ["o", "Ko", "Mo"],
  "nl-BE": ["B", "kB", "MB"],
  "de-DE": ["B", "kB", "MB"],
  "pt-BR": ["B", "KB", "MB"],
});

export function formatBytes(locale, bytes) {
  const normalized = normalizeLocale(locale);
  const value = Math.max(0, Number(bytes ?? 0));
  const units = byteUnits[normalized];
  if (value < 1024) return `${formatNumber(normalized, value, { maximumFractionDigits: 0 })} ${units[0]}`;
  if (value < 1024 * 1024) {
    return `${formatNumber(normalized, value / 1024, { minimumFractionDigits: 1, maximumFractionDigits: 1 })} ${units[1]}`;
  }
  return `${formatNumber(normalized, value / (1024 * 1024), { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${units[2]}`;
}

export function localizeScope(locale, verification) {
  const record = verification?.record ?? verification ?? {};
  if (record.specimen || verification?.specimen) {
    return {
      proves: translate(locale, "scope.specimen.proves"),
      attests: translate(locale, "scope.specimen.attests"),
      doesNotProve: translate(locale, "scope.specimen.limit"),
    };
  }

  const live = record.recordClass === "LIVE_CAPTURE_WEB";
  const storage = record.storage?.state === "STORED_ENCRYPTED"
    ? translate(locale, "scope.storage.present")
    : translate(locale, "scope.storage.absent");
  const qualified = record.qualifiedRail ?? {};
  const qualifiedVerified =
    qualified.state === "SANDBOX_TOKEN_ISSUED" &&
    qualified.signatureVerification === "VALID" &&
    qualified.certificateChainVerification === "VALID_TO_PINNED_SANDBOX_ROOT";
  const timestamp = qualified.state === "SANDBOX_TOKEN_ISSUED"
    ? translate(
        locale,
        qualifiedVerified ? "scope.timestamp.verified" : "scope.timestamp.unverified",
      )
    : translate(locale, "scope.timestamp.absent");
  const chainState = record.chainRail?.state;
  const chain = chainState === "FINALIZED"
    ? translate(locale, "scope.chain.finalized")
    : ["CONFIRMED", "SUBMITTED"].includes(chainState)
      ? translate(locale, "scope.chain.pending")
      : translate(locale, "scope.chain.absent");
  return {
    proves: [
      translate(locale, live ? "scope.live.proves" : "scope.import.proves"),
      storage,
      timestamp,
      chain,
    ].join(" "),
    attests: translate(locale, live ? "scope.live.attests" : "scope.import.attests"),
    doesNotProve: translate(locale, live ? "scope.live.limit" : "scope.import.limit"),
  };
}

export function localizeRailStatus(locale, rail, value) {
  const state = String(value?.state ?? "").toUpperCase();
  if (rail === "qualified") {
    if (state === "SANDBOX_TOKEN_ISSUED") {
      return translate(
        locale,
        value?.signatureVerification === "VALID" &&
          value?.certificateChainVerification === "VALID_TO_PINNED_SANDBOX_ROOT"
          ? "rail.qualified.verified"
          : "rail.qualified.unverified",
      );
    }
    if (state === "TOKEN_ISSUED") return translate(locale, "rail.qualified.production");
    return translate(locale, "rail.qualified.none");
  }
  const ids = {
    FINALIZED: "rail.chain.finalized",
    INVALID_ON_CHAIN: "rail.chain.invalid",
    FAILED_ON_CHAIN: "rail.chain.failed",
    CONFIRMED: "rail.chain.confirmed",
    SUBMITTED: "rail.chain.submitted",
  };
  return translate(locale, ids[state] ?? (state === "NOT_ANCHORED" ? "rail.chain.none" : "rail.chain.pending"));
}

export function localizeState(locale, state) {
  const ids = {
    FINALIZED: "status.finalized",
    CONFIRMED: "status.confirmed",
    SUBMITTED: "status.submitted",
    NOT_ANCHORED: "report.notAnchored",
    NOT_ISSUED: "report.notIssued",
    FAILED_ON_CHAIN: "status.error",
    INVALID_ON_CHAIN: "status.error",
  };
  return translate(locale, ids[String(state ?? "").toUpperCase()] ?? "report.unavailable");
}

export function catalogDiagnostics() {
  const keys = Object.keys(baseMessages).sort();
  return Object.fromEntries(SUPPORTED_LOCALES.map((locale) => {
    const catalog = catalogs[locale] ?? {};
    return [locale, {
      missing: keys.filter((key) => !Object.hasOwn(catalog, key)),
      extra: Object.keys(catalog).filter((key) => !Object.hasOwn(baseMessages, key)).sort(),
    }];
  }));
}
