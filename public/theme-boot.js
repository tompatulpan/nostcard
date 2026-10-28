/**
 * theme-boot.js — pre-paint boot script (classic script, loaded synchronously
 * from each page's <head>)
 *
 * 1. Applies the saved light/dark preference (or the system preference when
 *    nothing is saved) before the first paint so there is no flash of the
 *    wrong theme. The toggle lives in theme.js; the palette in css/theme.css.
 *    Keep the storage key in sync with STORAGE_KEYS.theme (utils.js).
 * 2. Hides the page (html.boot-pending) until i18n.js has loaded the locale
 *    and applied translations — the HTML ships with English placeholder
 *    text, which would otherwise flash before the Swedish strings arrive.
 *    A safety timeout reveals the page anyway if a module fails to load.
 *
 * Runs as a separate external file because the app CSP (script-src 'self')
 * forbids inline scripts.
 */
(function () {
  var root = document.documentElement;
  root.classList.add('boot-pending');
  setTimeout(function () { root.classList.remove('boot-pending'); }, 2000);
  try {
    var m = localStorage.getItem('e2e:theme');
    var dark = m === 'dark' ||
      (m !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    root.classList.toggle('dark-mode', dark);
  } catch (e) {}
})();
