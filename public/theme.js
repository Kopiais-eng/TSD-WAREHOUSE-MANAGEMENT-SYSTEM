
// =============================================================
// TSD WMS — Theme Loader
// Runs on every page. Reads the user's theme preference from
// localStorage (instant) and confirms with the server (async).
// Exposes window.setTheme() for the settings page to toggle.
// =============================================================

(function () {
  'use strict';

  const STORAGE_KEY = 'tsd-theme';
  const DEFAULT_THEME = 'dark';
  const VALID_THEMES = ['dark', 'light'];

  // ---------------------------------------------------------
  // 1) Apply cached theme IMMEDIATELY (before page paints)
  //    This prevents the "flash of wrong theme" issue.
  // ---------------------------------------------------------
  let cached = DEFAULT_THEME;
  try {
    cached = localStorage.getItem(STORAGE_KEY) || DEFAULT_THEME;
    if (!VALID_THEMES.includes(cached)) cached = DEFAULT_THEME;
  } catch (e) {
    // localStorage might be blocked (private mode, etc.) — fall back
    cached = DEFAULT_THEME;
  }

  document.documentElement.setAttribute('data-theme', cached);
  document.documentElement.setAttribute('data-theme-loaded', 'true');

  // ---------------------------------------------------------
  // 2) Fetch the theme from the server to confirm
  //    (in case the user changed it on another device/browser)
  // ---------------------------------------------------------
  function fetchServerTheme() {
    fetch('/api/user/theme', { credentials: 'include' })
      .then(function (res) {
        if (!res.ok) throw new Error('Failed to fetch theme');
        return res.json();
      })
      .then(function (data) {
        const serverTheme = (data && data.theme) || DEFAULT_THEME;
        if (!VALID_THEMES.includes(serverTheme)) return;

        // If server theme differs from what we have cached → update
        if (serverTheme !== document.documentElement.getAttribute('data-theme')) {
          document.documentElement.setAttribute('data-theme', serverTheme);
          try {
            localStorage.setItem(STORAGE_KEY, serverTheme);
          } catch (e) { /* ignore */ }
          window.dispatchEvent(new CustomEvent('themechange', { detail: { theme: serverTheme } }));
        }
      })
      .catch(function () {
        // Network error — keep the cached theme. No need to alert the user.
      });
  }

  // Only fetch if the user might be logged in (page isn't login.html)
  if (!/\/login(\.html)?$/.test(location.pathname)) {
    fetchServerTheme();
  }

  // ---------------------------------------------------------
  // 3) Public helper — call from anywhere to change the theme
  //    (settings.html uses this when the user clicks a theme card)
  // ---------------------------------------------------------
  window.setTheme = function (theme) {
    if (!VALID_THEMES.includes(theme)) {
      console.warn('[theme.js] Invalid theme:', theme);
      return;
    }
    document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch (e) { /* ignore */ }
    window.dispatchEvent(new CustomEvent('themechange', { detail: { theme: theme } }));
  };

  // ---------------------------------------------------------
  // 4) Public helper — read the current theme
  // ---------------------------------------------------------
  window.getTheme = function () {
    return document.documentElement.getAttribute('data-theme') || DEFAULT_THEME;
  };

  // ---------------------------------------------------------
  // 5) Cross-tab sync — if the user changes theme in another tab,
  //    update this tab too
  // ---------------------------------------------------------
  window.addEventListener('storage', function (e) {
    if (e.key === STORAGE_KEY && e.newValue && VALID_THEMES.includes(e.newValue)) {
      document.documentElement.setAttribute('data-theme', e.newValue);
      window.dispatchEvent(new CustomEvent('themechange', { detail: { theme: e.newValue } }));
    }
  });
})();
