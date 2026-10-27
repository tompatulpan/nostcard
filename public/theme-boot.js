/**
 * theme-boot.js — pre-paint theme application (classic script, loaded
 * synchronously from each page's <head>)
 *
 * Applies the saved light/dark preference (or the system preference when
 * nothing is saved) before the first paint so there is no flash of the
 * wrong theme. Runs under the app's CSP (script-src 'self' — no inline
 * scripts allowed), which is why it is a separate small file.
 *
 * The toggle itself lives in theme.js; the palette in css/theme.css.
 * Keep the storage key in sync with STORAGE_KEYS.theme (utils.js).
 */
(function () {
  try {
    var m = localStorage.getItem('e2e:theme');
    var dark = m === 'dark' ||
      (m !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.classList.toggle('dark-mode', dark);
  } catch (e) {}
})();
