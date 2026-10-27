/**
 * theme.js — Light/dark mode toggle for NostCard
 *
 * The active palette ("Classic" light + dark, adapted from the
 * contact-management-system "classic-refined" theme) lives in css/theme.css:
 *   light → :root tokens
 *   dark  → html.dark-mode tokens
 *
 * The class is applied before first paint by a tiny inline script in each
 * page's <head> (same storage key, below) so there is no flash of the wrong
 * theme. This module wires the toggle buttons, persists the choice, and
 * keeps the <meta name="theme-color"> in sync with the active surface.
 *
 * Usage: include  <script type="module" src="theme.js"></script>
 * Toggle: any element with  data-theme-toggle
 *
 * Security: writes only the e2e:theme preference to localStorage.
 * card.js restores it on public sessions, like the language preference.
 */

import { STORAGE_KEYS } from './utils.js';

const STORAGE_KEY = STORAGE_KEYS.theme;

/** @returns {boolean} true when the dark palette is active */
export function isDarkMode() {
  return document.documentElement.classList.contains('dark-mode');
}

/** Apply a mode ('light' | 'dark'); persist when the user chose it. */
export function setMode(mode, { persist = false, transition = false } = {}) {
  const root = document.documentElement;
  if (transition) root.classList.add('theme-transitioning');
  root.classList.toggle('dark-mode', mode === 'dark');
  if (persist) {
    try { localStorage.setItem(STORAGE_KEY, mode); } catch {}
  }
  _updateMetaThemeColor();
  _updateToggleIcons();
  if (transition) {
    setTimeout(() => root.classList.remove('theme-transitioning'), 300);
  }
}

/** Flip between light and dark (user action: persists + animates). */
export function toggleMode() {
  setMode(isDarkMode() ? 'light' : 'dark', { persist: true, transition: true });
}

// ---------------------------------------------------------------------------

function _updateToggleIcons() {
  document.querySelectorAll('[data-theme-toggle]').forEach(btn => {
    btn.textContent = isDarkMode() ? '☀️' : '🌙';
    btn.setAttribute('aria-pressed', isDarkMode() ? 'true' : 'false');
  });
}

/** Keep the browser UI (mobile address bar) in step with the active surface. */
function _updateMetaThemeColor() {
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', isDarkMode() ? '#161b26' : '#ffffff');
}

function _init() {
  // The head script already applied the saved/system preference — only
  // default to the system preference when nothing was stored (head script
  // handles it, but be safe if it ever fails).
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved !== 'light' && saved !== 'dark') {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      setMode(prefersDark ? 'dark' : 'light');
    }
  } catch {}
  _updateToggleIcons();
  _updateMetaThemeColor();
  document.querySelectorAll('[data-theme-toggle]').forEach(btn => {
    btn.addEventListener('click', toggleMode);
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _init);
} else {
  _init();
}
