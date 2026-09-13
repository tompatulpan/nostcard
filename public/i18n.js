/**
 * i18n.js — Lightweight internationalisation for nostr-vcard
 *
 * Usage:
 *   import { initI18n, t, setLang, getCurrentLang, applyTranslations } from './i18n.js';
 *
 *   await initI18n();              // detect language, load locale, apply to DOM
 *   t('some.key')                  // get translated string
 *   t('key.with.var', { n: 3 })    // with {{n}} interpolation
 *   setLang('sv');                 // switch language, persist, re-apply
 *
 * HTML attributes handled by applyTranslations():
 *   data-i18n              → el.textContent
 *   data-i18n-html         → el.innerHTML  (supports **bold** → <strong>; locale-controlled only)
 *   data-i18n-placeholder  → el.placeholder
 *   data-i18n-title        → el.title
 *
 * Locale files: public/locales/{lang}.json  (flat dot-notation keys)
 * Storage key:  e2e:lang
 * Fallback:     'sv'
 *
 * Security:
 *   data-i18n-html sets innerHTML — ONLY use with developer-controlled locale strings,
 *   NEVER with user-supplied data. User data must always go through textContent.
 */

export const SUPPORTED_LANGS = ['en', 'sv'];
const STORAGE_KEY = 'e2e:lang';

let _locale = {};
let _lang   = 'sv';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Detect language, load locale JSON, apply translations to the DOM. */
export async function initI18n() {
  _lang = _detectLang();
  await _loadLocale(_lang);
  applyTranslations();
}

/**
 * Look up a translation key. Returns the key itself if not found (never blank UI).
 * Interpolates {{varName}} placeholders using the vars object.
 */
export function t(key, vars = {}) {
  let str = Object.prototype.hasOwnProperty.call(_locale, key) ? _locale[key] : key;
  for (const [k, v] of Object.entries(vars)) {
    str = str.replaceAll(`{{${k}}}`, String(v));
  }
  return str;
}

/**
 * Walk the DOM and update all elements with i18n data-attributes.
 * Safe to call multiple times (called automatically by setLang).
 */
export function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    el.textContent = t(el.dataset.i18n);
  });
  // SECURITY: data-i18n-html values come ONLY from locale files, never from user input.
  document.querySelectorAll('[data-i18n-html]').forEach(el => {
    el.innerHTML = _processLocaleHtml(t(el.dataset.i18nHtml));
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  });
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    el.title = t(el.dataset.i18nTitle);
  });
  // Keep <html lang> attribute in sync for screen readers
  document.documentElement.lang = _lang;
}

/** Switch language, persist to localStorage, re-apply translations to DOM. */
export async function setLang(lang) {
  if (!SUPPORTED_LANGS.includes(lang)) return;
  _lang = lang;
  try { localStorage.setItem(STORAGE_KEY, lang); } catch {}
  await _loadLocale(lang);
  applyTranslations();
  window.dispatchEvent(new CustomEvent('i18n:changed', { detail: { lang } }));
}

/** Returns the currently active language code. */
export function getCurrentLang() { return _lang; }

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function _detectLang() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (SUPPORTED_LANGS.includes(stored)) return stored;
  } catch {}
  return 'sv';
}

async function _loadLocale(lang) {
  try {
    const res = await fetch(`./locales/${lang}.json`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    _locale = await res.json();
  } catch (err) {
    console.warn(`[i18n] Failed to load locale "${lang}":`, err.message);
    if (lang !== 'en') {
      // Fallback to English
      try {
        const res = await fetch('./locales/en.json');
        if (res.ok) { _locale = await res.json(); }
      } catch {}
    } else {
      _locale = {};
    }
  }
}

/**
 * Converts **bold** markdown to <strong> tags.
 * Other HTML in locale strings is passed through as-is.
 * SECURITY: locale strings are developer-controlled — never pass user data through this path.
 */
function _processLocaleHtml(str) {
  return str.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
}
