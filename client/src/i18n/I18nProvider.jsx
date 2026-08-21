import {
  Children,
  cloneElement,
  createContext,
  isValidElement,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  DEFAULT_LOCALE,
  LOCALE_OPTIONS,
  detectLocale,
  formatBytes,
  formatDateTime,
  formatNumber,
  googleLocaleFor,
  normalizeLocale,
  setActiveLocale,
  translate,
  translateSource,
} from "./index.js";

const STORAGE_KEY = "sitesealed.locale";
const TRANSLATABLE_PROPS = ["aria-label", "alt", "placeholder", "title"];
const I18nContext = createContext(null);

function initialLocale() {
  if (typeof window === "undefined") return DEFAULT_LOCALE;
  let stored = "";
  try {
    stored = window.localStorage.getItem(STORAGE_KEY) ?? "";
  } catch {
    // Storage can be disabled without disabling localization.
  }
  return detectLocale({
    search: window.location.search,
    stored,
    languages: window.navigator.languages ?? [window.navigator.language],
  });
}

function updateMeta(name, content, property = false) {
  if (typeof document === "undefined") return;
  const selector = property ? `meta[property="${name}"]` : `meta[name="${name}"]`;
  const element = document.querySelector(selector);
  if (element) element.setAttribute("content", content);
}

export function I18nProvider({ children }) {
  const [locale, setLocaleState] = useState(initialLocale);
  const normalizedLocale = normalizeLocale(locale);

  const value = useMemo(() => ({
    locale: normalizedLocale,
    options: LOCALE_OPTIONS,
    googleLocale: googleLocaleFor(normalizedLocale),
    setLocale: (nextLocale) => setLocaleState(normalizeLocale(nextLocale)),
    t: (id, variables) => translate(normalizedLocale, id, variables),
    translateText: (source) => translateSource(normalizedLocale, source),
    formatBytes: (bytes) => formatBytes(normalizedLocale, bytes),
    formatDateTime: (date, options) => formatDateTime(normalizedLocale, date, options),
    formatNumber: (number, options) => formatNumber(normalizedLocale, number, options),
  }), [normalizedLocale]);

  useEffect(() => {
    setActiveLocale(normalizedLocale);
    document.documentElement.lang = normalizedLocale;
    document.documentElement.dir = "ltr";
    document.title = value.t("meta.title");
    updateMeta("description", value.t("meta.description"));
    updateMeta("og:title", value.t("meta.title"), true);
    updateMeta("og:description", value.t("meta.description"), true);
    updateMeta("og:locale", normalizedLocale.replace("-", "_"), true);
    try {
      window.localStorage.setItem(STORAGE_KEY, normalizedLocale);
    } catch {
      // The active in-memory locale remains valid when storage is unavailable.
    }
    const url = new URL(window.location.href);
    url.searchParams.set("lang", normalizedLocale);
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
  }, [normalizedLocale, value]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  const value = useContext(I18nContext);
  if (!value) throw new Error("useI18n must be used inside I18nProvider");
  return value;
}

function translateWhitespacePreserving(value, translator) {
  const match = value.match(/^(\s*)([\s\S]*?)(\s*)$/);
  if (!match || !match[2]) return value;
  return `${match[1]}${translator(match[2])}${match[3]}`;
}

function localizeNode(node, translator) {
  if (typeof node === "string") return translateWhitespacePreserving(node, translator);
  if (Array.isArray(node)) return node.map((child) => localizeNode(child, translator));
  if (!isValidElement(node)) return node;
  if (node.props?.["data-i18n-skip"] === true || ["code", "pre", "kbd"].includes(node.type)) {
    return node;
  }
  const nextProps = {};
  for (const name of TRANSLATABLE_PROPS) {
    if (typeof node.props?.[name] === "string") {
      nextProps[name] = translateWhitespacePreserving(node.props[name], translator);
    }
  }
  if (node.props?.children !== undefined) {
    nextProps.children = Children.map(node.props.children, (child) => localizeNode(child, translator));
  }
  return cloneElement(node, nextProps);
}

export function Localized({ children }) {
  const { translateText } = useI18n();
  return localizeNode(children, translateText);
}

export function LanguageSelector({ className = "" }) {
  const { locale, options, setLocale, t } = useI18n();
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);
  const triggerRef = useRef(null);
  const listboxId = useId();
  const selected = options.find((option) => option.locale === locale) ?? options[0];

  useEffect(() => {
    if (!open) return undefined;
    const closeOutside = (event) => {
      if (!rootRef.current?.contains(event.target)) setOpen(false);
    };
    document.addEventListener("pointerdown", closeOutside);
    return () => document.removeEventListener("pointerdown", closeOutside);
  }, [open]);

  const optionButtons = () =>
    [...(rootRef.current?.querySelectorAll('[role="option"]') ?? [])];

  const focusOption = (index) => {
    const buttons = optionButtons();
    if (!buttons.length) return;
    buttons[(index + buttons.length) % buttons.length]?.focus();
  };

  const openAndFocus = (offset = 0) => {
    setOpen(true);
    requestAnimationFrame(() => {
      const selectedIndex = Math.max(
        0,
        options.findIndex((option) => option.locale === locale),
      );
      focusOption(selectedIndex + offset);
    });
  };

  const choose = (nextLocale) => {
    setLocale(nextLocale);
    setOpen(false);
    requestAnimationFrame(() => triggerRef.current?.focus());
  };

  const handleTriggerKeyDown = (event) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      openAndFocus(event.key === "ArrowDown" ? 0 : -1);
    }
  };

  const handleOptionKeyDown = (event) => {
    const buttons = optionButtons();
    const index = buttons.indexOf(event.currentTarget);
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      focusOption(index + (event.key === "ArrowDown" ? 1 : -1));
    } else if (event.key === "Home" || event.key === "End") {
      event.preventDefault();
      focusOption(event.key === "Home" ? 0 : buttons.length - 1);
    } else if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
      triggerRef.current?.focus();
    }
  };

  return (
    <div
      className={`language-selector${className ? ` ${className}` : ""}`}
      ref={rootRef}
    >
      <span className="sr-only">{t("language.label")}</span>
      <button
        className="language-selector__trigger"
        type="button"
        ref={triggerRef}
        aria-label={t("language.select")}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listboxId}
        onClick={() => (open ? setOpen(false) : openAndFocus())}
        onKeyDown={handleTriggerKeyDown}
      >
        <img className="language-selector__flag" src={selected.flag} alt="" width="22" height="15" />
        <span className="language-selector__selected-label">{selected.label}</span>
        <span className="language-selector__selected-short">{selected.shortLabel}</span>
        <span className="language-selector__chevron" aria-hidden="true" />
      </button>
      <div
        className={`language-selector__menu${open ? " language-selector__menu--open" : ""}`}
        id={listboxId}
        role="listbox"
        aria-label={t("language.select")}
      >
        {options.map((option) => (
          <button
            className="language-selector__option"
            key={option.locale}
            type="button"
            role="option"
            aria-selected={option.locale === locale}
            tabIndex={open ? 0 : -1}
            onClick={() => choose(option.locale)}
            onKeyDown={handleOptionKeyDown}
          >
            <img className="language-selector__flag" src={option.flag} alt="" width="22" height="15" />
            <span>{option.label}</span>
            <small>{option.shortLabel}</small>
          </button>
        ))}
      </div>
    </div>
  );
}
