/**
 * i18n.js — Lightweight internationalisation for NostCard
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

/**
 * Format an ISO date string using the active locale's date format.
 *   en → M/D/YYYY  (e.g. 9/21/2026)
 *   sv → YYYY-MM-DD (e.g. 2026-09-21)
 * Returns '' for falsy input.
 */
export function formatDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return '';
  const y = d.getFullYear();
  const m = d.getMonth() + 1;
  const day = d.getDate();
  return _lang === 'en'
    ? `${m}/${day}/${y}`
    : `${y}-${String(m).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
}

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
 * Other HTML in locale strings is limited to the localeHtml allowlist.
 * SECURITY: locale strings are developer-controlled — never pass user data through this path.
 */
function _processLocaleHtml(str) {
  return localeHtml(str).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
}

/**
 * Escape a locale string, then restore a fixed allowlist of formatting tags
 * (<code>, <kbd>, <strong>, <em>, <br>, the hint-mac <span>). Anything outside
 * the allowlist stays escaped, so a tampered locale file cannot inject
 * arbitrary markup into the page.
 * @param {string} str  Raw locale string (developer-controlled)
 * @returns {string}    HTML safe for innerHTML
 */
export function localeHtml(str) {
  let out = _escapeHtml(str);
  const TAGS = [
    ['&lt;code&gt;', '<code>'],   ['&lt;/code&gt;', '</code>'],
    ['&lt;kbd&gt;', '<kbd>'],     ['&lt;/kbd&gt;', '</kbd>'],
    ['&lt;strong&gt;', '<strong>'],['&lt;/strong&gt;', '</strong>'],
    ['&lt;em&gt;', '<em>'],       ['&lt;/em&gt;', '</em>'],
    ['&lt;br&gt;', '<br>'],
    ['&lt;span class=&quot;hint-mac&quot;&gt;', '<span class="hint-mac">'],
    ['&lt;/span&gt;', '</span>'],
  ];
  for (const [from, to] of TAGS) out = out.replaceAll(from, to);
  return out;
}

function _escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}
