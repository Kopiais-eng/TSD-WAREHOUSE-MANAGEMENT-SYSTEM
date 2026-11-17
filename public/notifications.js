// =============================================================
// TSD WMS — Notification Bell
// Auto-injects the bell + badge + dropdown into #notificationBell.
// Polls /api/notifications/unread-count every 30 seconds.
// Each notification row has an action button that navigates
// to the relevant page.
// =============================================================

(function () {
  'use strict';

  const POLL_INTERVAL = 30000;
  const BELL_CONTAINER_ID = 'notificationBell';

  // Icon per type
  const ICONS = {
    request_created:    '📨',
    request_approved:   '✅',
    request_rejected:   '❌',
    quotation_uploaded: '📄',
    quotation_approved: '✔️',
    quotation_rejected: '✖️',
    loan_created:       '🔁',
    loan_overdue:       '⚠️',
    loan_returned:      '📥',
    loan_paid:          '💰',
    test:               '🔔',
    info:               'ℹ️',
    // ⭐ NEW — for the newly wired events
    inventory_takeout:  '📤',
    inventory_added:    '➕',
    request_completed:  '🎉'
  };

  // Action button label per type
  const ACTION_LABELS = {
    request_created:    '📥 Review',
    request_approved:   '📄 Open',
    request_rejected:   '📄 Open',
    quotation_uploaded: '📄 Review Quote',
    quotation_approved: '💼 View',
    quotation_rejected: '💼 View',
    loan_created:       '📊 View Loan',
    loan_overdue:       '⚠️ Manage',
    loan_returned:      '📊 View',
    loan_paid:          '💰 View',
    test:               '➡️ Open',
    info:               '➡️ Open',
    // ⭐ NEW — for the newly wired events
    inventory_takeout:  '📦 Open Stock',
    inventory_added:    '📦 View',
    request_completed:  '🎉 Open'
  };

  let dropdownOpen = false;
  let pollTimer = null;

  // ---------------------------------------------------------
  function init() {
    const container = document.getElementById(BELL_CONTAINER_ID);
    if (!container) return;

    container.innerHTML = `
      <button class="bell-btn" id="bellBtn" aria-label="Notifications">
        <i data-lucide="bell" class="bell-icon"></i>
        <span class="bell-badge" id="bellBadge" style="display:none;">0</span>
      </button>
      <div class="bell-dropdown" id="bellDropdown" style="display:none;">
        <div class="bell-header">
          <span>Notifications</span>
          <button class="bell-mark-all" id="bellMarkAll">Mark all read</button>
        </div>
        <div class="bell-list" id="bellList">
          <div class="bell-empty">Loading...</div>
        </div>
        <div class="bell-footer">
          <a href="/settings.html#notifications">Notification settings</a>
        </div>
      </div>
    `;

    injectStyles();

    if (typeof lucide !== 'undefined' && typeof lucide.createIcons === 'function') {
    lucide.createIcons();
    }

    document.getElementById('bellBtn').addEventListener('click', toggleDropdown);
    document.getElementById('bellMarkAll').addEventListener('click', markAllRead);

    document.addEventListener('click', function (e) {
      const c = document.getElementById(BELL_CONTAINER_ID);
      if (dropdownOpen && c && !c.contains(e.target)) {
        closeDropdown();
      }
    });

    fetchUnreadCount();
    pollTimer = setInterval(fetchUnreadCount, POLL_INTERVAL);
  }

  // ---------------------------------------------------------
  async function fetchUnreadCount() {
    try {
      const res = await fetch('/api/notifications/unread-count', { credentials: 'include' });
      if (!res.ok) return;
      const data = await res.json();
      updateBadge(data.count || 0);
    } catch (e) { /* offline — ignore */ }
  }

  function updateBadge(count) {
    const badge = document.getElementById('bellBadge');
    if (!badge) return;
    if (count <= 0) {
      badge.style.display = 'none';
    } else {
      badge.style.display = 'flex';
      badge.textContent = count > 99 ? '99+' : count;
    }
  }

  // ---------------------------------------------------------
  function toggleDropdown() {
    if (dropdownOpen) closeDropdown();
    else openDropdown();
  }

  async function openDropdown() {
    dropdownOpen = true;
    const dd = document.getElementById('bellDropdown');
    dd.style.display = 'block';
    await loadNotifications();
  }

  function closeDropdown() {
    dropdownOpen = false;
    const dd = document.getElementById('bellDropdown');
    if (dd) dd.style.display = 'none';
  }

  // ---------------------------------------------------------
  async function loadNotifications() {
    const list = document.getElementById('bellList');
    list.innerHTML = '<div class="bell-empty">Loading...</div>';

    try {
      const res = await fetch('/api/notifications', { credentials: 'include' });
      if (!res.ok) throw new Error('Failed to fetch');
      const items = await res.json();

      if (items.length === 0) {
        list.innerHTML = '<div class="bell-empty">No notifications yet.</div>';
        return;
      }

      list.innerHTML = items.map(n => {
        const icon       = ICONS[n.type] || ICONS.info;
        const actionText = ACTION_LABELS[n.type] || ACTION_LABELS.info;
        const time       = timeAgo(n.created_at);
        const unreadClass = n.is_read ? '' : 'unread';
        const dot = n.is_read ? '' : '<span class="bell-dot"></span>';
        const hasLink = !!n.link;
        return `
          <div class="bell-item ${unreadClass}" data-id="${n.notification_id}" data-link="${n.link || ''}">
            <div class="bell-icon-cell">${icon}</div>
            <div class="bell-body">
              <div class="bell-msg">${escapeHtml(n.message)}</div>
              <div class="bell-meta">
                <span class="bell-time">${time}</span>
                ${hasLink ? `<button class="bell-action" data-id="${n.notification_id}" data-link="${n.link}">${actionText}</button>` : ''}
              </div>
            </div>
            ${dot}
          </div>
        `;
      }).join('');

      // Click on the action button → mark read + navigate
      list.querySelectorAll('.bell-action').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          e.stopPropagation();
          const id = btn.dataset.id;
          const link = btn.dataset.link;
          await markRead(id);
          if (link) window.location.href = link;
        });
      });

      // Click elsewhere on the row → mark read + navigate (same as button)
      list.querySelectorAll('.bell-item').forEach(el => {
        el.addEventListener('click', async () => {
          const id = el.dataset.id;
          const link = el.dataset.link;
          await markRead(id);
          if (link) window.location.href = link;
          else closeDropdown();
        });
      });
    } catch (e) {
      list.innerHTML = '<div class="bell-empty">Failed to load.</div>';
    }
  }

  // ---------------------------------------------------------
  async function markRead(id) {
    try {
      await fetch(`/api/notifications/${id}/read`, {
        method: 'PATCH',
        credentials: 'include'
      });
      const badge = document.getElementById('bellBadge');
      if (badge) {
        const n = parseInt(badge.textContent) || 0;
        updateBadge(Math.max(0, n - 1));
      }
    } catch (e) { /* ignore */ }
  }

  async function markAllRead(e) {
    e.stopPropagation();
    try {
      await fetch('/api/notifications/read-all', {
        method: 'PATCH',
        credentials: 'include'
      });
      updateBadge(0);
      await loadNotifications();
    } catch (e) { /* ignore */ }
  }

  // ---------------------------------------------------------
  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function timeAgo(ts) {
    const now = new Date();
    const then = new Date(ts);
    const diff = Math.floor((now - then) / 1000);

    if (diff < 60)     return 'just now';
    if (diff < 3600)   return `${Math.floor(diff / 60)} min ago`;
    if (diff < 86400)  return `${Math.floor(diff / 3600)} hr ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)} day${Math.floor(diff / 86400) > 1 ? 's' : ''} ago`;
    return then.toLocaleDateString();
  }

  // ---------------------------------------------------------
  function injectStyles() {
    if (document.getElementById('bell-styles')) return;
    const style = document.createElement('style');
    style.id = 'bell-styles';
    style.textContent = `
      #${BELL_CONTAINER_ID} {
        position: relative;
        display: inline-block;
      }

                /* ============ BELL THEME TOKENS ============ */
          /* Default = dark theme → white bell */
          :root,
          [data-theme="dark"] {
            --bell-bg:           #ffffff;
            --bell-fg:           #0f172a;
            --bell-border:       #e2e8f0;
            --bell-hover-bg:     #f1f5f9;
            --bell-hover-border: #cbd5e0;
          }

          /* Light theme → dark bell (matches sidebar #232c36) */
          [data-theme="light"] {
            --bell-bg:           #232c36;
            --bell-fg:           #ffffff;
            --bell-border:       #333333;
            --bell-hover-bg:     #2f3a47;
            --bell-hover-border: #3f4a58;
          }

          /* ============ BELL BUTTON ============ */
          .bell-btn {
            position: relative;
            width: 44px;
            height: 44px;
            border-radius: 50%;
            background: var(--bell-bg);
            border: 1px solid var(--bell-border);
            color: var(--bell-fg);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 0;
            transition: background 0.2s, border-color 0.2s, color 0.2s, transform 0.15s;
          }

          .bell-btn:hover {
            background: var(--bell-hover-bg);
            border-color: var(--bell-hover-border);
            color: var(--bell-fg);
            transform: translateY(-1px);
          }

          /* Lucide SVG sizing + inherits button color */
          .bell-btn .bell-icon,
          .bell-btn svg {
            width: 22px;
            height: 22px;
            stroke-width: 2.2;
            stroke: currentColor;
            color: inherit;
            display: block;
          }

          /* ============ BADGE ============ */
          .bell-badge {
            position: absolute;
            top: -4px;
            right: -4px;
            min-width: 20px;
            height: 20px;
            padding: 0 6px;
            background: #ef4444;
            color: #fff;
            font-size: 11px;
            font-weight: 700;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 2px solid var(--bell-bg);  /* ⭐ matches bell so it looks "cut out" */
            line-height: 1;
            pointer-events: none;
          }

      .bell-dropdown {
        position: absolute;
        top: calc(100% + 12px);
        right: 0;
        width: 400px;
        max-width: calc(100vw - 40px);
        background: var(--bg-card, #181f2b);
        border: 1px solid var(--border, #2a3344);
        border-radius: 14px;
        box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        z-index: 9999;
        overflow: hidden;
      }

      .bell-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 14px 18px;
        border-bottom: 1px solid var(--border-soft, #252f3f);
        font-size: 13px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: var(--text-primary, #e2e8f0);
      }

      .bell-mark-all {
        background: transparent;
        border: none;
        color: var(--accent, #ef4444);
        cursor: pointer;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.5px;
        font-family: inherit;
        padding: 0;
        text-transform: none;
      }
      .bell-mark-all:hover { text-decoration: underline; }

      .bell-list {
        max-height: 460px;
        overflow-y: auto;
      }

      .bell-empty {
        padding: 40px 20px;
        text-align: center;
        color: var(--text-muted, #7a8ba3);
        font-style: italic;
        font-size: 13px;
      }

      .bell-item {
        display: flex;
        align-items: flex-start;
        gap: 12px;
        padding: 14px 18px;
        border-bottom: 1px solid var(--border-row, #1f2a3a);
        cursor: pointer;
        transition: background 0.15s;
        position: relative;
      }
      .bell-item:hover { background: var(--bg-hover, #1a2332); }
      .bell-item.unread { background: rgba(239,68,68,0.06); }
      .bell-item.unread:hover { background: rgba(239,68,68,0.12); }

      .bell-icon-cell {
        font-size: 18px;
        flex-shrink: 0;
        line-height: 1.2;
        margin-top: 2px;
      }

      .bell-body { flex: 1; min-width: 0; }

      .bell-msg {
        font-size: 13px;
        color: var(--text-primary, #e2e8f0);
        line-height: 1.4;
        word-wrap: break-word;
        margin-bottom: 8px;
      }

      .bell-meta {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 10px;
      }

      .bell-time {
        font-size: 11px;
        color: var(--text-muted, #7a8ba3);
        flex-shrink: 0;
      }

      .bell-action {
        background: var(--accent, #ef4444);
        color: var(--accent-text, #fff);
        border: none;
        padding: 5px 12px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
        font-family: inherit;
        cursor: pointer;
        letter-spacing: 0.3px;
        transition: 0.15s;
        white-space: nowrap;
      }
      .bell-action:hover {
        background: var(--accent-hover, #dc2626);
        transform: translateY(-1px);
      }

      .bell-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--accent, #ef4444);
        flex-shrink: 0;
        margin-top: 6px;
      }

      .bell-footer {
        padding: 10px 18px;
        border-top: 1px solid var(--border-soft, #252f3f);
        text-align: center;
        font-size: 12px;
      }
      .bell-footer a {
        color: var(--text-muted, #7a8ba3);
        text-decoration: none;
      }
      .bell-footer a:hover { color: var(--accent, #ef4444); }

      @media (max-width: 480px) {
        .bell-dropdown {
          width: calc(100vw - 20px);
          right: -10px;
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