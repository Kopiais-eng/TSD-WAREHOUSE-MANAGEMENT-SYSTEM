// =============================================================
// TSD WMS — Shared HTML escaping helper
// Prevents stored XSS by encoding dangerous characters before
// any database value is inserted into innerHTML.
// Load this file on EVERY page, before any page-specific script.
// =============================================================
(function () {
  'use strict';

  function escapeHtml(value) {
    if (value == null) return '';
    return String(value)
      .replace(/&/g, '&amp;')   // must be first
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Escapes a value for safe use inside an HTML attribute
  // (e.g. value="...") — same rules, but also handles backticks.
  function escapeAttr(value) {
    if (value == null) return '';
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/`/g, '&#96;');
  }

  window.escapeHtml = escapeHtml;
  window.escapeAttr = escapeAttr;
})();