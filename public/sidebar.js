// =============================================================
// TSD WMS — Sidebar enhancements
// 1. Collapsible toggle (persisted in localStorage)
// 2. Filters sidebar buttons by role (data-roles attribute)
// 3. Live unread-email badge (polled every 20s)
// 4. Auto-highlights the current page's button
// 5. Uses Lucide icons (SVG, theme-aware)
// =============================================================

(function () {
  'use strict';

  const STORAGE_KEY    = 'tsd-sidebar-collapsed';
  const EMAIL_POLL_MS  = 20000;

  let emailPollTimer = null;

  // ---------------------------------------------------------
  function init() {
    const sidebar = document.querySelector('.sidebar');
    if (!sidebar) return;

    injectToggle(sidebar);
    applySavedCollapse(sidebar);
    injectStyles();

    // Fetch user → hide buttons by role → set active → render icons
    filterByRole(sidebar)
      .then(() => {
        setActiveByPath(sidebar);
        renderLucideIcons();
      });
  }

  // ---------------------------------------------------------
  // 1) Collapse toggle
  // ---------------------------------------------------------
  function injectToggle(sidebar) {
    const btn = document.createElement('button');
    btn.className = 'sidebar-toggle';
    btn.setAttribute('aria-label', 'Toggle sidebar');
    btn.innerHTML = '<span class="toggle-icon">‹</span>';
    sidebar.appendChild(btn);

    btn.addEventListener('click', function () {
      sidebar.classList.toggle('collapsed');
      const isCollapsed = sidebar.classList.contains('collapsed');
      try { localStorage.setItem(STORAGE_KEY, isCollapsed ? '1' : '0'); } catch (e) {}
    });
  }

  function applySavedCollapse(sidebar) {
    let collapsed = false;
    try { collapsed = localStorage.getItem(STORAGE_KEY) === '1'; } catch (e) {}
    if (collapsed) sidebar.classList.add('collapsed');
  }

  // ---------------------------------------------------------
  // 2) Hide buttons by role (reads data-roles attribute)
  // ---------------------------------------------------------
  async function filterByRole(sidebar) {
    let role = null;

    try {
      const res = await fetch('/api/me', { credentials: 'include' });
      const data = await res.json();
      if (!data.user) return;
      role = data.user.role;
    } catch (e) {
      return;   // Not logged in / network error
    }

    // Hide any button whose data-roles list doesn't include this role
    sidebar.querySelectorAll('[data-roles]').forEach(btn => {
      const allowed = btn.getAttribute('data-roles')
        .split(',')
        .map(r => r.trim())
        .filter(Boolean);

      if (!allowed.includes(role)) {
        btn.style.display = 'none';
      } else {
        btn.style.display = '';
      }
    });

    // Attach email badge to the Emails button (only if this user sees it)
    const emailBtn = sidebar.querySelector('[onclick*="/emails.html"]');
    if (emailBtn && (role === 'admin' || role === 'finance')) {
      ensureBadgeOn(sidebar, emailBtn);
      startEmailPolling();
    }
  }

  // ---------------------------------------------------------
  // 3) Auto-highlight current page
  // ---------------------------------------------------------
  function setActiveByPath(sidebar) {
    const currentPage = location.pathname.split('/').pop() || 'dashboard.html';

    sidebar.querySelectorAll('.side-btn').forEach(btn => btn.classList.remove('active'));

    // Find the button whose onclick contains the current filename
    const match = [...sidebar.querySelectorAll('.side-btn')].find(btn => {
      const onclick = btn.getAttribute('onclick') || '';
      return onclick.includes(`/${currentPage}`);
    });

    if (match) match.classList.add('active');
  }

  // ---------------------------------------------------------
  // Badge helper
  // ---------------------------------------------------------
  function ensureBadgeOn(sidebar, btn) {
    if (btn.querySelector('.email-badge')) return;
    const badge = document.createElement('span');
    badge.className = 'email-badge';
    badge.id = 'emailBadge';
    btn.appendChild(badge);
  }

  function startEmailPolling() {
    updateEmailBadge();
    clearInterval(emailPollTimer);
    emailPollTimer = setInterval(updateEmailBadge, EMAIL_POLL_MS);
  }

  // ---------------------------------------------------------
  // 4) Unread email badge
  // ---------------------------------------------------------
  async function updateEmailBadge() {
    const badge = document.getElementById('emailBadge');
    if (!badge) return;
    try {
      const res = await fetch('/api/emails/unread-count', { credentials: 'include' });
      if (!res.ok) return;
      const data = await res.json();
      const n = data.count || 0;
      badge.textContent = n > 0 ? (n > 99 ? '99+' : String(n)) : '';
    } catch (e) { /* ignore */ }
  }

  window.__refreshEmailBadge = updateEmailBadge;

  // ---------------------------------------------------------
  // 5) Lucide icon rendering helper
  // ---------------------------------------------------------
  function renderLucideIcons() {
    if (typeof lucide !== 'undefined' && typeof lucide.createIcons === 'function') {
      lucide.createIcons();
    }
  }

  // ---------------------------------------------------------
  // Styles
  // ---------------------------------------------------------
  function injectStyles() {
    if (document.getElementById('sidebar-collapse-styles')) return;

    const style = document.createElement('style');
    style.id = 'sidebar-collapse-styles';
    style.textContent = `
      /* ---------- Smooth width transition ---------- */
      .sidebar {
        transition: width 0.25s ease, padding 0.25s ease;
        position: relative;
      }

      /* ---------- Lucide icon sizing (normal mode) ---------- */
      .side-btn svg {
        width: 18px;
        height: 18px;
        flex-shrink: 0;
        stroke-width: 1.8;
      }

      /* ---------- COLLAPSED STATE ---------- */
      .sidebar.collapsed {
        width: 70px;
        padding: 30px 10px;
      }

      .sidebar.collapsed .logo,
      .sidebar.collapsed .logo-sub {
        display: none;
      }

      /* Center the icon, hide the label */
      .sidebar.collapsed .side-btn {
        justify-content: center;
        padding: 12px 0;
        gap: 0;
        position: relative;
      }
      .sidebar.collapsed .side-btn span:not(.email-badge) {
        display: none;
      }
      .sidebar.collapsed .side-btn svg {
        width: 22px;
        height: 22px;
      }

      /* Badge on collapsed sidebar */
      .sidebar.collapsed .side-btn .email-badge {
        position: absolute;
        top: 4px;
        right: 4px;
        font-size: 9px;
        min-width: 16px;
        height: 16px;
        line-height: 16px;
        padding: 0 4px;
        border-radius: 8px;
        margin: 0;
      }

      /* ---------- TOGGLE BUTTON ---------- */
      .sidebar-toggle {
        position: absolute;
        top: 24px;
        right: -14px;
        width: 28px;
        height: 28px;
        border-radius: 50%;
        background: var(--bg-elevated);
        border: 1px solid var(--border);
        color: var(--text-primary);
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 0;
        z-index: 100;
        transition: 0.2s ease;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
      }
      .sidebar-toggle:hover {
        background: var(--accent);
        color: var(--accent-text);
        border-color: var(--accent);
        transform: scale(1.1);
      }
      .sidebar-toggle .toggle-icon {
        font-size: 18px;
        font-weight: 700;
        line-height: 1;
        display: inline-block;
        transition: transform 0.25s ease;
        margin-top: -5px;
      }
      .sidebar.collapsed .sidebar-toggle .toggle-icon {
        transform: rotate(180deg);
        margin-top: 5px;
      }

      /* ---------- EMAIL UNREAD BADGE ---------- */
      .email-badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        background: #ef4444;
        color: #ffffff;
        font-size: 10px;
        font-weight: 700;
        padding: 1px 6px;
        border-radius: 10px;
        margin-left: auto;
        min-width: 18px;
        height: 18px;
        line-height: 1;
        letter-spacing: 0;
        text-transform: none;
      }
      .email-badge:empty {
        display: none;
      }

      /* ---------- Mobile ---------- */
      @media (max-width: 768px) {
        .sidebar-toggle {
          display: none;
        }
      }
    `;
    document.head.appendChild(style);
  }

  // ---------------------------------------------------------
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();