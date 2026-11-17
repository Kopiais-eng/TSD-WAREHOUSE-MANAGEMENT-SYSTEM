require('dotenv').config();
const express = require('express');
const https = require('https');
const { Pool } = require('pg');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');

// ---------- EMAIL ----------
const SMTP_USER = process.env.SMTP_USER || 'your-email@gmail.com';
const SMTP_PASS = process.env.SMTP_PASS || 'your-app-password-here';
const EMAIL_FROM = process.env.EMAIL_FROM || `"TSD WMS" <${SMTP_USER}>`;

const IMAP_HOST = process.env.IMAP_HOST || 'mail.examedia.my';
const IMAP_PORT = parseInt(process.env.IMAP_PORT || '993');
const IMAP_USER = process.env.IMAP_USER || SMTP_USER;
const IMAP_PASS = process.env.IMAP_PASS || SMTP_PASS;

const emailTransporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST || 'smtp.gmail.com',
  port:   parseInt(process.env.SMTP_PORT || '465'),
  secure: true,
  auth: { user: SMTP_USER, pass: SMTP_PASS },
  tls: { rejectUnauthorized: false }
});

const app = express();
const port = 3000;

// ---------- Exa Claim SO Code API ----------
const EXA_API_URL = process.env.EXA_CLAIM_API_URL;
const EXA_API_KEY = process.env.EXA_CLAIM_API_KEY;
const SO_SYNC_INTERVAL_MS = 15 * 60 * 1000;  // auto-sync every 15 min

if (!EXA_API_URL || !EXA_API_KEY) {
  console.warn('⚠️  Exa Claim SO Code env not set — sync endpoints will fail.');
}

// ---------- UPLOAD: quotations ----------
const uploadDir = path.join(__dirname, 'uploads', 'quotations');
fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + ext);
  }
});

// ---------- DATABASE ----------
const pool = new Pool({
  host:     process.env.DB_HOST     || '172.16.2.70',
  port:     parseInt(process.env.DB_PORT || '5432'),
  user:     process.env.DB_USER     || 'postgres',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME     || 'postgres'
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg','image/png','image/webp','image/gif','application/pdf'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Only images and PDFs are allowed.'));
  }
});

// ---------- UPLOAD: email attachments ----------
const emailUploadDir = path.join(__dirname, 'uploads', 'emails');
const emailReceivedDir = path.join(emailUploadDir, 'received');
fs.mkdirSync(emailUploadDir,   { recursive: true });
fs.mkdirSync(emailReceivedDir, { recursive: true });

const emailStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, emailUploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + ext);
  }
});

const emailUpload = multer({
  storage: emailStorage,
  limits: { fileSize: 15 * 1024 * 1024 }
});

// ---------- MIDDLEWARE ----------
app.use(express.json({ limit: '2mb' }));
app.use(express.static('public'));

// ---------- Session secret guard ----------
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('❌ FATAL: SESSION_SECRET missing or too short in .env');
  console.error('   Generate one with:  openssl rand -hex 32');
  process.exit(1);
}

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: true,
    sameSite: 'lax'         // ⭐ bonus: also fixes part of issue #5
  }
}));

// =============================================================
// AUTH-PROTECTED UPLOADS
// Serves files from /uploads/* only to authenticated users
// with the appropriate role.
// =============================================================
app.use('/uploads',
  isAuthenticated,
  function (req, res, next) {
    // req.path is relative to /uploads, e.g. /quotations/abc.jpg
    const rel = req.path || '';

    // Quotations — admin, manager, finance only
    if (rel.startsWith('/quotations/')) {
      if (!['admin', 'manager', 'finance'].includes(req.session.role)) {
        return res.status(403).json({ error: 'Forbidden.' });
      }
      return next();
    }

    // Email attachments (sent + received) — admin, manager, finance
    if (rel.startsWith('/emails/')) {
      if (!['admin', 'manager', 'finance'].includes(req.session.role)) {
        return res.status(403).json({ error: 'Forbidden.' });
      }
      return next();
    }

    // Anything else under /uploads → not found
    return res.status(404).json({ error: 'Not found.' });
  },
  express.static(path.join(__dirname, 'uploads'), {
    // Prevent directory listing & hidden files
    dotfiles: 'deny',
    index: false
  })
);

// ---------- AUTH MIDDLEWARE ----------
function isAuthenticated(req, res, next) {
  if (req.session.userId) return next();
  res.status(401).json({ error: 'Unauthorized. Please log in.' });
}

function hasRole(requiredRoles) {
  return (req, res, next) => {
    if (req.session.role === 'admin' || requiredRoles.includes(req.session.role)) return next();
    res.status(403).json({ error: 'Forbidden. Insufficient permissions.' });
  };
}

// ---------- AUDIT LOG HELPER ----------
async function logAudit(req, {
  entityType, entityId, action, itemPart, itemSerial, itemClient,
  inventoryId, requestId, loanId, qty, fromStatus, toStatus, notes
}) {
  try {
    await pool.query(
      `INSERT INTO audit_log
        (user_id, user_name, user_role, entity_type, entity_id, action,
         item_part, item_serial, item_client, inventory_id, request_id, loan_id,
         qty, from_status, to_status, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
      [
        req.session.userId || null,
        req.session.fullName || 'Unknown',
        req.session.role || null,
        entityType, entityId || null, action,
        itemPart || null, itemSerial || null, itemClient || null,
        inventoryId || null, requestId || null, loanId || null,
        qty || null, fromStatus || null, toStatus || null, notes || null
      ]
    );
  } catch (err) {
    console.error('logAudit failed:', err.message);
  }
}

// =============================================================
// EXA CLAIM — SO CODE SYNC HELPERS
// =============================================================
async function fetchAllSOCodesFromExa(updatedSince = null) {
  if (!EXA_API_URL || !EXA_API_KEY) {
    throw new Error('Exa Claim env not configured.');
  }

  const allItems = [];
  let cursor = null;
  let pageCount = 0;
  const MAX_PAGES = 200;         // safety limit
  const MAX_RETRIES = 3;

  do {
    const url = new URL('/api/v1/so-codes', EXA_API_URL);
    url.searchParams.set('limit', '100');
    if (cursor) url.searchParams.set('cursor', cursor);
    if (updatedSince) url.searchParams.set('updatedSince', updatedSince);

    let attempt = 0;
    let ok = false;
    let payload = null;
    let lastErr = null;

    while (attempt < MAX_RETRIES && !ok) {
      attempt++;
      try {
        const res = await fetch(url, {
          headers: {
            Authorization: `Bearer ${EXA_API_KEY}`,
            Accept: 'application/json'
          }
        });

        // 429 → backoff + retry
        if (res.status === 429) {
          const wait = 1000 * Math.pow(2, attempt) + Math.random() * 500;
          console.warn(`[exa-sync] 429 rate-limited — waiting ${Math.round(wait)}ms`);
          await new Promise(r => setTimeout(r, wait));
          continue;
        }

        // 5xx → retry
        if (res.status >= 500) {
          const wait = 1000 * Math.pow(2, attempt);
          console.warn(`[exa-sync] ${res.status} — retrying in ${wait}ms`);
          await new Promise(r => setTimeout(r, wait));
          lastErr = new Error(`Exa Claim HTTP ${res.status}`);
          continue;
        }

        payload = await res.json();

        if (!res.ok) {
          // 4xx (except 429) → don't retry
          throw new Error(`Exa Claim ${res.status}: ${payload?.error || 'unknown'}`);
        }

        if (!payload.success) {
          throw new Error(`Exa Claim error: ${payload.error || 'unknown'}`);
        }

        ok = true;
      } catch (e) {
        lastErr = e;
        if (attempt >= MAX_RETRIES) throw e;
        await new Promise(r => setTimeout(r, 1000 * attempt));
      }
    }

    if (!ok) throw lastErr || new Error('Exa Claim request failed');

    allItems.push(...(payload.data.items || []));
    cursor = payload.data.nextCursor;
    pageCount++;
    if (pageCount >= MAX_PAGES) {
      console.warn('[exa-sync] hit page limit, stopping early');
      break;
    }
  } while (cursor);

  return allItems;
}

async function upsertSOCodes(items) {
  if (!items || items.length === 0) return { inserted: 0, updated: 0, total: 0 };

  let inserted = 0, updated = 0;
  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');
    for (const item of items) {
      const result = await dbClient.query(
        `INSERT INTO so_codes (
           id, exa_no, so_number, partner_customer, description,
           price_exc_sst, sst, price_inc_sst, status,
           contract_period, allocated_budget,
           exa_created_at, exa_updated_at, last_synced_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
         ON CONFLICT (id) DO UPDATE SET
           exa_no           = EXCLUDED.exa_no,
           so_number        = EXCLUDED.so_number,
           partner_customer = EXCLUDED.partner_customer,
           description      = EXCLUDED.description,
           price_exc_sst    = EXCLUDED.price_exc_sst,
           sst              = EXCLUDED.sst,
           price_inc_sst    = EXCLUDED.price_inc_sst,
           status           = EXCLUDED.status,
           contract_period  = EXCLUDED.contract_period,
           allocated_budget = EXCLUDED.allocated_budget,
           exa_created_at   = EXCLUDED.exa_created_at,
           exa_updated_at   = EXCLUDED.exa_updated_at,
           last_synced_at   = NOW()
         RETURNING (xmax = 0) AS inserted`,
        [
          item.id,
          item.no             || null,
          item.soNumber       || null,
          item.partnerCustomer || null,
          item.description    || null,
          item.priceExcSst    || null,
          item.sst            || null,
          item.priceIncSst    || null,
          item.status         || null,
          item.contractPeriod || null,
          item.allocatedBudget || null,
          item.createdAt      || null,
          item.updatedAt      || null
        ]
      );
      if (result.rows[0].inserted) inserted++;
      else updated++;
    }
    await dbClient.query('COMMIT');
  } catch (e) {
    await dbClient.query('ROLLBACK');
    throw e;
  } finally {
    dbClient.release();
  }

  return { inserted, updated, total: items.length };
}

async function syncSOCodes(updatedSince = null) {
  const items = await fetchAllSOCodesFromExa(updatedSince);
  const stats = await upsertSOCodes(items);
  console.log(`[exa-sync] ${stats.total} fetched · ${stats.inserted} new · ${stats.updated} updated`);
  return stats;
}

// =============================================================
// EMAIL HELPERS
// =============================================================

let lastSyncAt = 0;
const SYNC_COOLDOWN_MS = 30 * 1000;

function buildRfqSubject(request) {
  const part = request.part || 'item';
  return `[REQ-${request.request_id}] Request for Quotation — ${part}`;
}

function parseRequestIdFromSubject(subject) {
  if (!subject) return null;
  const m = String(subject).match(/\[REQ-(\d+)\]/i);
  return m ? parseInt(m[1], 10) : null;
}

function makePreview(body, max = 200) {
  if (!body) return '';
  const clean = String(body).replace(/\s+/g, ' ').trim();
  return clean.length > max ? clean.slice(0, max) + '…' : clean;
}

async function syncInbox({ force = false } = {}) {
  const now = Date.now();
  if (!force && (now - lastSyncAt) < SYNC_COOLDOWN_MS) {
    return { skipped: true, reason: 'cooldown', lastSync: new Date(lastSyncAt).toISOString() };
  }
  lastSyncAt = now;

  const client = new ImapFlow({
    host: IMAP_HOST,
    port: IMAP_PORT,
    secure: true,
    auth: { user: IMAP_USER, pass: IMAP_PASS },
    logger: false
  });

  const summary = { fetched: 0, matched: 0, unmatched: 0, errors: [] };

  try {
    await client.connect();
    const lock = await client.getMailboxLock('INBOX');

    try {
      const status = client.mailbox;
      const total  = status.exists || 0;
      if (total === 0) return summary;

      const start = Math.max(1, total - 39);
      const range = `${start}:*`;

      for await (const msg of client.fetch(range, { source: true, envelope: true, uid: true })) {
        try {
          const parsed = await simpleParser(msg.source);
          const messageId = parsed.messageId || `no-id-${msg.uid}`;

          const existing = await pool.query(
            'SELECT email_id FROM email_log WHERE message_id = $1',
            [messageId]
          );
          if (existing.rows.length > 0) continue;

          summary.fetched++;

          const fromAddr = parsed.from?.value?.[0]?.address || 'unknown';
          const toAddr   = parsed.to?.value?.[0]?.address   || IMAP_USER;
          const subject  = parsed.subject || '(no subject)';
          const bodyText = parsed.text || parsed.html || '';
          const bodyPrev = makePreview(bodyText);
          const reqId    = parseRequestIdFromSubject(subject);

          const attachments = [];
          if (parsed.attachments && parsed.attachments.length) {
            for (const att of parsed.attachments) {
              try {
                const safeName = (att.filename || 'attachment').replace(/[^\w.\-]/g, '_');
                const fname = `${Date.now()}-${Math.round(Math.random()*1e6)}-${safeName}`;
                const fpath = path.join(emailReceivedDir, fname);
                fs.writeFileSync(fpath, att.content);
                attachments.push({
                  filename: att.filename || fname,
                  stored: `/uploads/emails/received/${fname}`,
                  size: att.size || att.content?.length || 0,
                  mimetype: att.contentType || 'application/octet-stream'
                });
              } catch (e) {
                console.error('Attachment save failed:', e.message);
              }
            }
          }

          await pool.query(
            `INSERT INTO email_log
              (request_id, direction, from_email, to_email, subject,
               body_preview, body_full, message_id, in_reply_to, attachments, is_read)
             VALUES ($1,'received',$2,$3,$4,$5,$6,$7,$8,$9::jsonb,FALSE)`,
            [
              reqId, fromAddr, toAddr, subject,
              bodyPrev, bodyText.slice(0, 50000),
              messageId, parsed.inReplyTo || null,
              JSON.stringify(attachments)
            ]
          );

          if (reqId) summary.matched++; else summary.unmatched++;
        } catch (e) {
          summary.errors.push(e.message);
        }
      }
    } finally {
      lock.release();
    }
  } catch (e) {
    summary.errors.push('IMAP: ' + e.message);
  } finally {
    try { await client.logout(); } catch (_) {}
  }

  return summary;
}

// =============================================================
// AUTH ROUTES
// =============================================================

app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  try {
    const result = await pool.query(
      'SELECT user_id, username, role, full_name, email FROM users WHERE user_id = $1',
      [req.session.userId]
    );
    if (result.rows.length === 0) { req.session.destroy(); return res.json({ user: null }); }
    res.json({ user: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid username or password.' });
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid username or password.' });
    req.session.userId = user.user_id;
    req.session.role = user.role;
    req.session.fullName = user.full_name;
    res.json({ message: 'Login successful', user: { user_id: user.user_id, username: user.username, role: user.role, full_name: user.full_name } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ⭐ LOCKED — admin only
app.post('/api/register', isAuthenticated, hasRole(['admin']), async (req, res) => {
  const {
    username, password, full_name, email, role, department,
    employee_code, designation, phone, cost_center,
    direct_manager, reporting_manager
  } = req.body;

  if (!username || !password || !full_name || !role) {
    return res.status(400).json({ error: 'Username, password, full name, and role are required.' });
  }

  const validRoles = ['admin', 'manager', 'finance', 'technician', 'user'];
  if (!validRoles.includes(role)) return res.status(400).json({ error: 'Invalid role selected.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  try {
    const existing = await pool.query('SELECT 1 FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Username already taken.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, role, full_name, email, department,
                          employee_code, designation, phone, cost_center,
                          direct_manager, reporting_manager)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING user_id, username, full_name, email, role, department,
                 employee_code, designation, phone, cost_center,
                 direct_manager, reporting_manager`,
      [
        username, hashedPassword, role, full_name, email || null, department || null,
        employee_code || null, designation || null, phone || null, cost_center || null,
        direct_manager || null, reporting_manager || null
      ]
    );
    res.status(201).json({ message: 'User created successfully!', user: result.rows[0] });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: 'Logout failed.' });
    res.json({ message: 'Logout successful' });
  });
});

// =============================================================
// USERS MANAGEMENT (admin only)
// =============================================================

app.get('/api/users', isAuthenticated, hasRole(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT user_id, username, full_name, email, role, department,
             employee_code, designation, phone, cost_center,
             direct_manager, reporting_manager
      FROM users
      ORDER BY user_id
    `);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/users/:id', isAuthenticated, hasRole(['admin']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid user ID.' });

  const {
    full_name, email, role, department,
    employee_code, designation, phone, cost_center,
    direct_manager, reporting_manager
  } = req.body;

  if (id === req.session.userId && role && role !== 'admin') {
    return res.status(400).json({ error: 'You cannot change your own role.' });
  }

  const validRoles = ['admin', 'manager', 'finance', 'technician', 'user'];
  if (role && !validRoles.includes(role)) {
    return res.status(400).json({ error: 'Invalid role.' });
  }

  try {
    const result = await pool.query(`
      UPDATE users SET
        full_name          = COALESCE($1,  full_name),
        email              = COALESCE($2,  email),
        role               = COALESCE($3,  role),
        department         = COALESCE($4,  department),
        employee_code      = COALESCE($5,  employee_code),
        designation        = COALESCE($6,  designation),
        phone              = COALESCE($7,  phone),
        cost_center        = COALESCE($8,  cost_center),
        direct_manager     = COALESCE($9,  direct_manager),
        reporting_manager  = COALESCE($10, reporting_manager)
      WHERE user_id = $11
      RETURNING user_id, username, full_name, email, role, department,
                employee_code, designation, phone, cost_center,
                direct_manager, reporting_manager
    `, [
      full_name || null, email || null, role || null, department || null,
      employee_code || null, designation || null, phone || null, cost_center || null,
      direct_manager || null, reporting_manager || null, id
    ]);

    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found.' });
    res.json({ message: 'User updated.', user: result.rows[0] });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users/:id/reset-password', isAuthenticated, hasRole(['admin']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid user ID.' });

  const { new_password } = req.body;
  if (!new_password || new_password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }

  try {
    const hash = await bcrypt.hash(new_password, 10);
    const result = await pool.query(
      'UPDATE users SET password_hash = $1 WHERE user_id = $2 RETURNING username',
      [hash, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found.' });

    res.json({ message: `Password reset for ${result.rows[0].username}.` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// NOTIFICATIONS
// =============================================================
async function notify(userIds, { type, message, link }) {
  if (!Array.isArray(userIds)) userIds = [userIds];
  userIds = userIds.filter(id => id != null);
  if (userIds.length === 0) return;
  try {
    const values = userIds.map(uid => [uid, type || 'info', message, link || null]);
    const placeholders = values.map((_, i) =>
      `($${i * 4 + 1}, $${i * 4 + 2}, $${i * 4 + 3}, $${i * 4 + 4})`
    ).join(', ');
    const flat = values.flat();
    await pool.query(
      `INSERT INTO notifications (user_id, type, message, link)
       VALUES ${placeholders}`,
      flat
    );
  } catch (err) {
    console.error('notify() failed:', err.message);
  }
}

async function getAdminIds() {
  try {
    const r = await pool.query("SELECT user_id FROM users WHERE role = 'admin'");
    return r.rows.map(x => x.user_id);
  } catch (e) { return []; }
}
async function getManagerIds() {
  try {
    const r = await pool.query("SELECT user_id FROM users WHERE role = 'manager'");
    return r.rows.map(x => x.user_id);
  } catch (e) { return []; }
}
async function getFinanceIds() {
  try {
    const r = await pool.query("SELECT user_id FROM users WHERE role = 'finance'");
    return r.rows.map(x => x.user_id);
  } catch (e) { return []; }
}

app.get('/api/notifications', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT notification_id, type, message, link, is_read, created_at
       FROM notifications WHERE user_id = $1
       ORDER BY created_at DESC LIMIT 30`,
      [req.session.userId]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/notifications/unread-count', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT COUNT(*)::int AS count FROM notifications
       WHERE user_id = $1 AND is_read = FALSE`,
      [req.session.userId]
    );
    res.json({ count: result.rows[0].count });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/notifications/:id/read', isAuthenticated, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid notification ID.' });
  try {
    const result = await pool.query(
      `UPDATE notifications SET is_read = TRUE
       WHERE notification_id = $1 AND user_id = $2 RETURNING *`,
      [id, req.session.userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not found.' });
    res.json({ message: 'Marked as read.', notification: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/notifications/read-all', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE notifications SET is_read = TRUE
       WHERE user_id = $1 AND is_read = FALSE`,
      [req.session.userId]
    );
    res.json({ message: 'All marked as read.', updated: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/notifications/test', isAuthenticated, hasRole(['admin']), async (req, res) => {
  const { message, link } = req.body;
  await notify(req.session.userId, {
    type: 'test',
    message: message || 'Test notification — hello!',
    link: link || null
  });
  res.json({ message: 'Test notification created.' });
});

// =============================================================
// SETTINGS ROUTES
// =============================================================
app.get('/api/user/preferences', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT user_id, username, full_name, email, role, department,
              employee_code, designation, cost_center,
              direct_manager, reporting_manager, phone,
              pref_theme, pref_accent, pref_compact, pref_rows_per_page,
              pref_date_format, pref_email_loans, pref_email_requests
       FROM users WHERE user_id = $1`,
      [req.session.userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found.' });
    const u = result.rows[0];
    res.json({
      user: {
        user_id: u.user_id,
        username: u.username,
        full_name: u.full_name,
        email: u.email,
        role: u.role,
        department: u.department,
        employee_code: u.employee_code,
        designation: u.designation,
        cost_center: u.cost_center,
        direct_manager: u.direct_manager,
        reporting_manager: u.reporting_manager,
        phone: u.phone
      },
      preferences: {
        theme: u.pref_theme || 'dark',
        accent: u.pref_accent || 'red',
        compact: u.pref_compact || false,
        rows_per_page: u.pref_rows_per_page || 25,
        date_format: u.pref_date_format || 'DD/MM/YYYY',
        email_loans: u.pref_email_loans ?? true,
        email_requests: u.pref_email_requests ?? true
      }
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/user/preferences', isAuthenticated, async (req, res) => {
  const { theme, accent, compact, rows_per_page, date_format, email_loans, email_requests } = req.body;
  const validThemes   = ['dark', 'light'];
  const validAccents  = ['red', 'blue', 'green', 'yellow', 'purple'];
  const validFormats  = ['DD/MM/YYYY', 'MM/DD/YYYY', 'YYYY-MM-DD'];
  const validRows     = [10, 25, 50, 100];
  if (theme && !validThemes.includes(theme))       return res.status(400).json({ error: 'Invalid theme.' });
  if (accent && !validAccents.includes(accent))    return res.status(400).json({ error: 'Invalid accent.' });
  if (date_format && !validFormats.includes(date_format)) return res.status(400).json({ error: 'Invalid date format.' });
  if (rows_per_page && !validRows.includes(parseInt(rows_per_page))) return res.status(400).json({ error: 'Invalid rows per page.' });
  try {
    const result = await pool.query(
      `UPDATE users SET
         pref_theme          = COALESCE($1, pref_theme),
         pref_accent         = COALESCE($2, pref_accent),
         pref_compact        = COALESCE($3, pref_compact),
         pref_rows_per_page  = COALESCE($4, pref_rows_per_page),
         pref_date_format    = COALESCE($5, pref_date_format),
         pref_email_loans    = COALESCE($6, pref_email_loans),
         pref_email_requests = COALESCE($7, pref_email_requests)
       WHERE user_id = $8
       RETURNING pref_theme, pref_accent, pref_compact, pref_rows_per_page,
                 pref_date_format, pref_email_loans, pref_email_requests`,
      [
        theme || null, accent || null,
        typeof compact === 'boolean' ? compact : null,
        rows_per_page ? parseInt(rows_per_page) : null,
        date_format || null,
        typeof email_loans === 'boolean' ? email_loans : null,
        typeof email_requests === 'boolean' ? email_requests : null,
        req.session.userId
      ]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found.' });
    const u = result.rows[0];
    res.json({
      message: 'Preferences saved.',
      preferences: {
        theme: u.pref_theme, accent: u.pref_accent, compact: u.pref_compact,
        rows_per_page: u.pref_rows_per_page, date_format: u.pref_date_format,
        email_loans: u.pref_email_loans, email_requests: u.pref_email_requests
      }
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/change-password', isAuthenticated, async (req, res) => {
  const { current_password, new_password, confirm_password } = req.body;
  if (!current_password || !new_password) return res.status(400).json({ error: 'Current and new password are required.' });
  if (new_password.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  if (confirm_password !== undefined && new_password !== confirm_password) return res.status(400).json({ error: 'New passwords do not match.' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE user_id = $1', [req.session.userId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found.' });
    const user = result.rows[0];
    const match = await bcrypt.compare(current_password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Current password is incorrect.' });
    if (await bcrypt.compare(new_password, user.password_hash)) return res.status(400).json({ error: 'New password must be different from current password.' });
    const newHash = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE user_id = $2', [newHash, req.session.userId]);
    console.log(`✅ Password changed for user ${user.username}`);
    res.json({ message: 'Password updated successfully.' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/user/profile', isAuthenticated, async (req, res) => {
  const {
    full_name, email, phone,
    employee_code, designation,
    department, cost_center,
    direct_manager, reporting_manager
  } = req.body;

  const isAdmin = (req.session.role === 'admin');
  const userId  = req.session.userId;

  try {
    if (!isAdmin) {
      const restrictedFields = [
        { field: 'department',        value: department },
        { field: 'cost_center',       value: cost_center },
        { field: 'direct_manager',    value: direct_manager },
        { field: 'reporting_manager', value: reporting_manager }
      ];

      for (const { field, value } of restrictedFields) {
        if (!value) continue;
        const check = await pool.query(
          `SELECT 1 FROM users WHERE ${field} = $1 LIMIT 1`, [value]
        );
        if (check.rows.length === 0) {
          return res.status(403).json({ error: `Only admin can create new ${field.replace('_', ' ')} values.` });
        }
      }
    }

    const result = await pool.query(
      `UPDATE users SET
         full_name          = COALESCE($1, full_name),
         email              = COALESCE($2, email),
         phone              = COALESCE($3, phone),
         employee_code      = COALESCE($4, employee_code),
         designation        = COALESCE($5, designation),
         department         = COALESCE($6, department),
         cost_center        = COALESCE($7, cost_center),
         direct_manager     = COALESCE($8, direct_manager),
         reporting_manager  = COALESCE($9, reporting_manager)
       WHERE user_id = $10
       RETURNING user_id, username, full_name, email, role, department,
                 employee_code, designation, cost_center,
                 direct_manager, reporting_manager, phone`,
      [
        full_name       || null,
        email           || null,
        phone           || null,
        employee_code   || null,
        designation     || null,
        department      !== undefined ? (department || null)        : null,
        cost_center     !== undefined ? (cost_center || null)       : null,
        direct_manager  !== undefined ? (direct_manager || null)    : null,
        reporting_manager !== undefined ? (reporting_manager || null) : null,
        userId
      ]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found.' });

    if (full_name) req.session.fullName = full_name;

    res.json({ message: 'Profile updated.', user: result.rows[0] });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: err.message });
  }
});

// =============================================================
// OPTIONS (departments / cost centers / managers)
// =============================================================
function optionsRoutes(table, label) {
  app.get(`/api/options/${label}`, isAuthenticated, async (req, res) => {
    try {
      const r = await pool.query(`SELECT id, name FROM ${table} ORDER BY name`);
      res.json(r.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post(`/api/options/${label}`, isAuthenticated, hasRole(['admin']), async (req, res) => {
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'Name is required.' });
    try {
      const r = await pool.query(
        `INSERT INTO ${table} (name) VALUES ($1)
         ON CONFLICT (name) DO NOTHING
         RETURNING id, name`,
        [name]
      );
      if (r.rows.length === 0) return res.status(400).json({ error: 'Value already exists.' });
      res.json(r.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.delete(`/api/options/${label}/:id`, isAuthenticated, hasRole(['admin']), async (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID.' });

    try {
      const found = await pool.query(`SELECT name FROM ${table} WHERE id = $1`, [id]);
      if (found.rows.length === 0) return res.status(404).json({ error: 'Option not found.' });
      const name = found.rows[0].name;

      const columnMap = {
        option_departments:  'department',
        option_cost_centers: 'cost_center',
        option_managers:     'direct_manager'
      };
      const col = columnMap[table];
      let usageCheck;
      if (table === 'option_managers') {
        usageCheck = await pool.query(
          `SELECT COUNT(*)::int AS c FROM users WHERE direct_manager = $1 OR reporting_manager = $1`,
          [name]
        );
      } else {
        usageCheck = await pool.query(
          `SELECT COUNT(*)::int AS c FROM users WHERE ${col} = $1`,
          [name]
        );
      }
      const inUse = usageCheck.rows[0].c;

      await pool.query(`DELETE FROM ${table} WHERE id = $1`, [id]);

      res.json({ message: 'Option deleted.', used_by: inUse });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });
}

optionsRoutes('option_departments',  'departments');
optionsRoutes('option_cost_centers', 'cost-centers');
optionsRoutes('option_managers',     'managers');

// =============================================================
// INVENTORY ROUTES
// =============================================================
app.get('/api/inventory', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT i.*,
              s.so_number      AS so_number,
              s.partner_customer AS so_customer,
              s.status         AS so_status
       FROM inventory i
       LEFT JOIN so_codes s ON i.so_code_id = s.id
       ORDER BY i.inventory_id`
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/inventory', isAuthenticated, hasRole(['admin', 'manager', 'technician']), async (req, res) => {
  const { client, category, part, description, rack, serials, so_code_id } = req.body;
const cleanSoCodeId = so_code_id && String(so_code_id).trim() ? String(so_code_id).trim() : null;

  if (!client || !category || !part || !description || !rack) {
    return res.status(400).json({ error: 'Client, category, part, description, and rack are required.' });
  }
  if (!Array.isArray(serials) || serials.length === 0) {
    return res.status(400).json({ error: 'At least one serial number is required.' });
  }
  const cleanSerials = serials.map(s => String(s || '').trim()).filter(Boolean);
  if (cleanSerials.length !== serials.length) {
    return res.status(400).json({ error: 'All serial number fields must be filled.' });
  }
  const dup = cleanSerials.filter((s, i) => cleanSerials.indexOf(s) !== i);
  if (dup.length) {
    return res.status(400).json({ error: `Duplicate serial in submission: ${dup[0]}` });
  }
  const finalQty = cleanSerials.length;

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');

        // Reject if serial already exists FOR THIS CLIENT
    const conflict = await dbClient.query(
      `SELECT s.serial FROM inventory_serials s
       JOIN inventory i ON s.inventory_id = i.inventory_id
       WHERE s.serial = ANY($1::text[]) AND i.client = $2`,
      [cleanSerials, client]
    );
    if (conflict.rows.length > 0) {
      await dbClient.query('ROLLBACK');
      return res.status(400).json({
        error: `Serial already exists for client ${client}: ${conflict.rows.map(r => r.serial).join(', ')}`
      });
    }

    const existing = await dbClient.query(
      `SELECT * FROM inventory
       WHERE category = $1 AND part = $2 AND client = $3 AND rack = $4
       FOR UPDATE`,
      [category, part, client, rack]
    );

    let invRow;
    if (existing.rows.length > 0) {
      invRow = existing.rows[0];
      const upd = await dbClient.query(
        `UPDATE inventory SET qty = qty + $1 WHERE inventory_id = $2 RETURNING *`,
        [finalQty, invRow.inventory_id]
      );
      invRow = upd.rows[0];
    } else {
      const ins = await dbClient.query(
        `INSERT INTO inventory (client, category, part, serial, description, qty, rack, so_code_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
        [client, category, part, cleanSerials[0], description, finalQty, rack, cleanSoCodeId]
      );
      invRow = ins.rows[0];
    }

    const vals = [];
    const params = [];
    cleanSerials.forEach((s, i) => {
      const b = i * 3;
      vals.push(`($${b + 1}, $${b + 2}, $${b + 3})`);
      params.push(invRow.inventory_id, s, req.session.userId);
    });
    await dbClient.query(
      `INSERT INTO inventory_serials (inventory_id, serial, added_by)
       VALUES ${vals.join(', ')}`,
      params
    );

    await dbClient.query('COMMIT');

    const adminIds = await getAdminIds();
    await notify(adminIds, {
      type: 'inventory_added',
      message: `${req.session.fullName || 'User'} added ${finalQty}× ${part} (${category}) at ${client} — Rack ${rack}`,
      link: '/inventory.html'
    });
    await logAudit(req, {
      entityType: 'inventory',
      entityId: invRow.inventory_id,
      action: 'inventory.added',
      itemPart: part,
      itemSerial: cleanSerials.join(', '),
      itemClient: client,
      inventoryId: invRow.inventory_id,
      qty: finalQty,
      toStatus: 'in_stock',
      notes: `${category} — Rack ${rack}`
    });

    res.json({ ...invRow, serials_added: cleanSerials });
  } catch (err) {
    await dbClient.query('ROLLBACK');
    console.error('[POST /api/inventory]', err);
    res.status(500).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

// ⭐ Multi-serial takeout (dispose)
app.patch('/api/inventory/:id/takeout', isAuthenticated, hasRole(['admin', 'manager', 'technician']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid inventory ID.' });

  const serialIds = Array.isArray(req.body?.serial_ids)
    ? req.body.serial_ids.map(x => parseInt(x)).filter(Boolean)
    : [];

  if (serialIds.length === 0) {
    return res.status(400).json({ error: 'At least one serial must be selected.' });
  }

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');

    const invRes = await dbClient.query(
      `SELECT * FROM inventory WHERE inventory_id = $1 FOR UPDATE`, [id]
    );
    if (invRes.rows.length === 0) {
      await dbClient.query('ROLLBACK');
      return res.status(404).json({ error: 'Item not found.' });
    }
    const item = invRes.rows[0];
    const currentQty = parseInt(item.qty) || 0;
    if (currentQty < serialIds.length) {
      await dbClient.query('ROLLBACK');
      return res.status(400).json({ error: `Only ${currentQty} in stock.` });
    }

    const check = await dbClient.query(
      `SELECT serial_id, serial FROM inventory_serials
       WHERE serial_id = ANY($1::int[])
         AND inventory_id = $2
         AND status = 'in_stock'
       FOR UPDATE`,
      [serialIds, id]
    );
    if (check.rows.length !== serialIds.length) {
      await dbClient.query('ROLLBACK');
      return res.status(400).json({ error: 'One or more serials are not in stock.' });
    }
    const serialList = check.rows.map(r => r.serial);

    await dbClient.query(
      `UPDATE inventory_serials
       SET status = 'taken_out', removed_at = NOW(), removed_by = $1
       WHERE serial_id = ANY($2::int[])`,
      [req.session.userId, serialIds]
    );

    const newQty = currentQty - serialIds.length;
    const upd = await dbClient.query(
      `UPDATE inventory SET qty = $1 WHERE inventory_id = $2 RETURNING *`,
      [newQty, id]
    );

    await dbClient.query('COMMIT');

    const adminIds = await getAdminIds();
    await notify(adminIds, {
      type: 'inventory_takeout',
      message: `${req.session.fullName || 'User'} disposed ${serialIds.length}× ${item.part} (${newQty} left)`,
      link: '/inventory.html'
    });
    await logAudit(req, {
      entityType: 'inventory', entityId: id,
      action: 'inventory.taken_out',
      itemPart: item.part, itemSerial: serialList.join(', '), itemClient: item.client,
      inventoryId: id, qty: serialIds.length,
      fromStatus: 'in_stock',
      toStatus: newQty === 0 ? 'empty' : 'in_stock',
      notes: `Disposed ${serialIds.length} serial(s): ${serialList.join(', ')}`
    });

    res.json({
      message: `${serialIds.length} unit(s) disposed. ${newQty} remaining.`,
      item: upd.rows[0],
      serials: serialList
    });
  } catch (err) {
    await dbClient.query('ROLLBACK');
    console.error('[takeout]', err);
    res.status(500).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

// =============================================================
// INVENTORY — EDIT ITEM METADATA
// =============================================================
app.patch('/api/inventory/:id', isAuthenticated, hasRole(['admin', 'manager', 'technician']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid inventory ID.' });

  const { client, category, part, description, rack, so_code_id } = req.body;
  const cleanSoCodeId = so_code_id && String(so_code_id).trim() ? String(so_code_id).trim() : null;

  if (!client || !category || !part || !description || !rack) {
    return res.status(400).json({ error: 'Client, category, part, description, and rack are required.' });
  }

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');
    
    const origRes = await dbClient.query('SELECT * FROM inventory WHERE inventory_id = $1', [id]);
    if (origRes.rows.length === 0) {
      await dbClient.query('ROLLBACK');
      return res.status(404).json({ error: 'Item not found.' });
    }
    const orig = origRes.rows[0];

    if (cleanSoCodeId) {
      const soCheck = await dbClient.query('SELECT status FROM so_codes WHERE id = $1', [cleanSoCodeId]);
      if (soCheck.rows.length === 0 || soCheck.rows[0].status !== 'OPEN') {
        await dbClient.query('ROLLBACK');
        return res.status(400).json({ error: 'Selected SO Code not found or not OPEN.' });
      }
    }

    const result = await dbClient.query(
      `UPDATE inventory SET 
         client = $1, category = $2, part = $3, description = $4, rack = $5, so_code_id = $6
       WHERE inventory_id = $7 RETURNING *`,
      [client, category, part, description, rack, cleanSoCodeId, id]
    );

    await dbClient.query('COMMIT');

    await logAudit(req, {
      entityType: 'inventory', entityId: id,
      action: 'inventory.updated',
      itemPart: part, itemSerial: orig.serial, itemClient: client,
      inventoryId: id,
      notes: `Updated details.`
    });

    res.json({ message: 'Item updated successfully.', item: result.rows[0] });
  } catch (err) {
    await dbClient.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

app.get('/api/inventory/:id/serials', isAuthenticated, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid inventory ID.' });
  try {
    const result = await pool.query(
      `SELECT s.serial_id, s.serial, s.status, s.added_at, s.removed_at,
              u1.username AS added_by_name,
              u2.username AS removed_by_name
       FROM inventory_serials s
       LEFT JOIN users u1 ON s.added_by   = u1.user_id
       LEFT JOIN users u2 ON s.removed_by = u2.user_id
       WHERE s.inventory_id = $1
       ORDER BY
         CASE s.status
           WHEN 'in_stock' THEN 0
           WHEN 'reserved' THEN 1
           WHEN 'loaned'   THEN 2
           ELSE 3
         END,
         s.added_at ASC`,
      [id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('[serials]', err);
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/inventory/:id/assign', isAuthenticated, hasRole(['admin', 'technician']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid inventory ID.' });
  const { hostname, ip_address, rack_position, warranty_expiry, assigned_engineer } = req.body;
  try {
    const check = await pool.query('SELECT * FROM inventory WHERE inventory_id = $1', [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Item not found.' });
    const result = await pool.query(
      `UPDATE inventory SET hostname = $1, ip_address = $2, rack_position = $3,
       warranty_expiry = $4, assigned_engineer = $5, asset_status = 'assigned'
       WHERE inventory_id = $6 RETURNING *`,
      [hostname, ip_address, rack_position, warranty_expiry, assigned_engineer, id]
    );
    await logAudit(req, {
      entityType: 'inventory', entityId: id,
      action: 'inventory.assigned',
      itemPart: result.rows[0].part,
      itemSerial: result.rows[0].serial,
      itemClient: result.rows[0].client,
      inventoryId: id,
      toStatus: 'assigned',
      notes: `Assigned to ${assigned_engineer || 'engineer'}`
    });
    res.json({ message: 'Asset assigned.', item: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// INVENTORY — BULK IMPORT (EXCEL)
// =============================================================
// =============================================================
// INVENTORY — BULK IMPORT (EXCEL)
// =============================================================
app.post('/api/inventory/bulk', isAuthenticated, hasRole(['admin', 'manager', 'technician']), async (req, res) => {
  const { items } = req.body;
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'No items provided.' });
  }

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');
    let successCount = 0;

    // 1. Prepare the timestamp and counter for blank serials
    let noneCounter = 1;
    const importTimestamp = Date.now().toString().slice(-6); // e.g. "849201"

    // 2. Group by Client + Category + Part(Asset Tag) + Description + Rack + SO Code
    const groups = {};

    for (const row of items) {
      let soCodeId = null;
      if (row.so_code) {
        const soCheck = await dbClient.query('SELECT id FROM so_codes WHERE so_number = $1', [String(row.so_code).trim()]);
        if (soCheck.rows.length > 0) soCodeId = soCheck.rows[0].id;
      }

      // Use 'None' as Asset Tag if blank
      const partName = row.part && row.part.trim() !== '' ? row.part.trim() : 'None';
      
      // Convert "None" rack to empty
      const rackName = row.rack && row.rack.toLowerCase() !== 'none' ? row.rack.trim() : null;

      const key = `${row.client}|${row.category}|${partName}|${row.description}|${rackName}|${soCodeId || ''}`;
      
      if (!groups[key]) {
        groups[key] = {
          client: row.client,
          category: row.category,
          part: partName,
          description: row.description,
          rack: rackName,
          so_code_id: soCodeId,
          serials: []
        };
      }

      // 3. Handle blanks for serial numbers (auto-generate UNIQUE placeholders)
      let finalSerial = row.serial ? String(row.serial).trim() : '';
      if (!finalSerial) {
        finalSerial = `NONE-${importTimestamp}-${noneCounter++}`;
      }
      groups[key].serials.push(finalSerial);
    }

    // 4. Process each group
    for (const key in groups) {
      const g = groups[key];
      const finalQty = g.serials.length;
      if (finalQty === 0) continue;

      // Check for duplicates in database
            // Check for duplicates in database FOR THIS CLIENT
      const conflict = await dbClient.query(
        `SELECT s.serial FROM inventory_serials s
         JOIN inventory i ON s.inventory_id = i.inventory_id
         WHERE s.serial = ANY($1::text[]) AND i.client = $2`,
        [g.serials, g.client]
      );
      if (conflict.rows.length > 0) {
        throw new Error(`Serial already exists for client ${g.client}: ${conflict.rows.map(r => r.serial).join(', ')}`);
      }

      // Find existing inventory row or create a new one
      const existing = await dbClient.query(
        `SELECT * FROM inventory WHERE category = $1 AND part = $2 AND client = $3 AND rack IS NOT DISTINCT FROM $4 AND description IS NOT DISTINCT FROM $5 FOR UPDATE`,
        [g.category, g.part, g.client, g.rack, g.description]
      );

      let invId;
      if (existing.rows.length > 0) {
        invId = existing.rows[0].inventory_id;
        await dbClient.query(
          `UPDATE inventory SET qty = qty + $1, so_code_id = COALESCE($2, so_code_id) WHERE inventory_id = $3`,
          [finalQty, g.so_code_id, invId]
        );
      } else {
        const ins = await dbClient.query(
          `INSERT INTO inventory (client, category, part, serial, description, qty, rack, so_code_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING inventory_id`,
          [g.client, g.category, g.part, g.serials[0], g.description, finalQty, g.rack, g.so_code_id]
        );
        invId = ins.rows[0].inventory_id;
      }

      // Insert serials
      const vals = [];
      const params = [];
      g.serials.forEach((s, i) => {
        const b = i * 3;
        vals.push(`($${b + 1}, $${b + 2}, $${b + 3})`);
        params.push(invId, s, req.session.userId);
      });
      await dbClient.query(
        `INSERT INTO inventory_serials (inventory_id, serial, added_by) VALUES ${vals.join(', ')}`,
        params
      );
      successCount += finalQty;
    }

    await dbClient.query('COMMIT');
    
    // Audit log
    await logAudit(req, {
      entityType: 'inventory',
      action: 'inventory.bulk_imported',
      qty: successCount,
      notes: `Imported ${successCount} items via Excel`
    });

    res.json({ message: `Successfully imported ${successCount} items.`, count: successCount });

  } catch (err) {
    await dbClient.query('ROLLBACK');
    console.error('[bulk import]', err);
    res.status(500).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

// =============================================================
// ASSET ROUTES  (department-owned items, no qty, no loan)
// =============================================================
app.get('/api/assets', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT a.*,
              u1.username AS added_by_name,
              u2.username AS removed_by_name
       FROM assets a
       LEFT JOIN users u1 ON a.added_by   = u1.user_id
       LEFT JOIN users u2 ON a.removed_by = u2.user_id
       ORDER BY
         CASE a.status WHEN 'in_stock' THEN 0 ELSE 1 END,
         a.asset_id DESC`
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/assets', isAuthenticated, hasRole(['admin', 'technician']), async (req, res) => {
  const { part, serial, category, description, rack } = req.body;
  if (!part || !serial || !category) {
    return res.status(400).json({ error: 'Item name, serial number, and category are required.' });
  }
  const cleanSerial = String(serial).trim();
  try {
    const dup = await pool.query('SELECT 1 FROM assets WHERE serial = $1', [cleanSerial]);
    if (dup.rows.length > 0) {
      return res.status(400).json({ error: `Serial "${cleanSerial}" already exists.` });
    }
    const result = await pool.query(
      `INSERT INTO assets (part, serial, category, description, rack, added_by)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [String(part).trim(), cleanSerial, category, description || null, rack || null, req.session.userId]
    );
    await logAudit(req, {
      entityType: 'asset', entityId: result.rows[0].asset_id,
      action: 'asset.added',
      itemPart: part, itemSerial: cleanSerial, qty: 1,
      toStatus: 'in_stock',
      notes: `${category}${rack ? ' — Rack ' + rack : ''}`
    });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// ASSETS — Take Out (borrow) / Decompose (dispose)
// =============================================================

app.patch('/api/assets/:id/takeout', isAuthenticated, hasRole(['admin', 'technician']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid asset ID.' });

  const { taken_out_by, notes } = req.body;
  if (!taken_out_by || !String(taken_out_by).trim()) {
    return res.status(400).json({ error: 'Please specify who is taking this asset out.' });
  }

  try {
    const check = await pool.query('SELECT * FROM assets WHERE asset_id = $1', [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Asset not found.' });
    const asset = check.rows[0];
    if (asset.status === 'taken_out') {
      return res.status(400).json({ error: 'Asset is already taken out.' });
    }
    if (asset.status === 'decomposed') {
      return res.status(400).json({ error: 'Asset is already decomposed.' });
    }

    const result = await pool.query(
      `UPDATE assets SET
         status          = 'taken_out',
         taken_out_by    = $1,
         taken_out_at    = NOW(),
         taken_out_notes = $2
       WHERE asset_id = $3 RETURNING *`,
      [String(taken_out_by).trim(), (notes || '').toString().trim() || null, id]
    );

    await logAudit(req, {
      entityType: 'asset', entityId: id,
      action: 'asset.taken_out',
      itemPart: asset.part, itemSerial: asset.serial,
      qty: 1, fromStatus: 'in_stock', toStatus: 'taken_out',
      notes: `Taken out by ${String(taken_out_by).trim()}${notes ? ' — ' + notes : ''}`
    });

    res.json({ message: `Asset taken out by ${String(taken_out_by).trim()}.`, asset: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// ASSETS — Return (from taken_out back to in_stock)
// =============================================================
app.patch('/api/assets/:id/return', isAuthenticated, hasRole(['admin', 'technician']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid asset ID.' });

  try {
    const check = await pool.query('SELECT * FROM assets WHERE asset_id = $1', [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Asset not found.' });
    const asset = check.rows[0];

    if (asset.status === 'in_stock') {
      return res.status(400).json({ error: 'Asset is already in stock.' });
    }
    if (asset.status === 'decomposed') {
      return res.status(400).json({ error: 'Cannot return a decomposed asset.' });
    }

    const result = await pool.query(
      `UPDATE assets SET
         status      = 'in_stock',
         returned_at = NOW(),
         returned_by = $1
       WHERE asset_id = $2 RETURNING *`,
      [req.session.userId, id]
    );

    await logAudit(req, {
      entityType: 'asset', entityId: id,
      action: 'asset.returned',
      itemPart: asset.part, itemSerial: asset.serial,
      qty: 1, fromStatus: 'taken_out', toStatus: 'in_stock',
      notes: asset.taken_out_by ? `Returned by ${asset.taken_out_by}` : 'Returned'
    });

    res.json({ message: `Asset "${asset.part}" returned to stock.`, asset: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// ASSETS — Decompose
// =============================================================
app.patch('/api/assets/:id/decompose', isAuthenticated, hasRole(['admin', 'technician']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid asset ID.' });

  const { notes } = req.body;

  try {
    const check = await pool.query('SELECT * FROM assets WHERE asset_id = $1', [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Asset not found.' });
    const asset = check.rows[0];
    if (asset.status === 'decomposed') {
      return res.status(400).json({ error: 'Asset is already decomposed.' });
    }

    const result = await pool.query(
      `UPDATE assets SET
         status           = 'decomposed',
         decomposed_at    = NOW(),
         decomposed_by    = $1,
         decomposed_notes = $2
       WHERE asset_id = $3 RETURNING *`,
      [req.session.userId, (notes || '').toString().trim() || null, id]
    );

    await logAudit(req, {
      entityType: 'asset', entityId: id,
      action: 'asset.decomposed',
      itemPart: asset.part, itemSerial: asset.serial,
      qty: 1, fromStatus: asset.status, toStatus: 'decomposed',
      notes: notes ? String(notes).trim() : 'Disposed'
    });

    res.json({ message: `Asset "${asset.part}" marked as decomposed.`, asset: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// ASSETS — History (reads audit_log for one asset)
// =============================================================
app.get('/api/assets/:id/history', isAuthenticated, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid asset ID.' });

  try {
    const assetRes = await pool.query(
      `SELECT a.*,
              u1.username AS added_by_name,
              u2.username AS decomposed_by_name,
              u3.username AS returned_by_name
       FROM assets a
       LEFT JOIN users u1 ON a.added_by      = u1.user_id
       LEFT JOIN users u2 ON a.decomposed_by = u2.user_id
       LEFT JOIN users u3 ON a.returned_by   = u3.user_id
       WHERE a.asset_id = $1`,
      [id]
    );
    if (assetRes.rows.length === 0) return res.status(404).json({ error: 'Asset not found.' });

    const historyRes = await pool.query(
      `SELECT log_id, user_name, user_role, action,
              from_status, to_status, notes, created_at
       FROM audit_log
       WHERE entity_type = 'asset' AND entity_id = $1
       ORDER BY created_at ASC`,
      [id]
    );

    res.json({
      asset: assetRes.rows[0],
      history: historyRes.rows
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// LOAN ROUTES
// =============================================================
app.get('/api/loans', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT l.*, u.username AS issued_by_name
       FROM loans l LEFT JOIN users u ON l.issued_by = u.user_id
       ORDER BY (l.status = 'active') DESC, l.due_date ASC, l.loan_id DESC`
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ⭐ Loans now require serial_ids
app.post('/api/loans', isAuthenticated, hasRole(['admin']), async (req, res) => {
  const { inventory_id, customer_name, contact_person, contact_phone, contact_email,
          qty, due_date, rate, notes, serial_ids } = req.body;

  if (!customer_name || !qty || !due_date) {
    return res.status(400).json({ error: 'Customer name, quantity, and due date are required.' });
  }
  if (!inventory_id) {
    return res.status(400).json({ error: 'Inventory item is required.' });
  }
  const loanQty = parseInt(qty);

  const cleanSerialIds = Array.isArray(serial_ids)
    ? serial_ids.map(x => parseInt(x)).filter(Boolean)
    : [];

  if (cleanSerialIds.length !== loanQty) {
    return res.status(400).json({ error: 'Serial count must match loan quantity.' });
  }

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');
    const invRes = await dbClient.query(
      'SELECT * FROM inventory WHERE inventory_id = $1 FOR UPDATE', [inventory_id]
    );
    if (invRes.rows.length === 0) {
      await dbClient.query('ROLLBACK');
      return res.status(404).json({ error: 'Inventory item not found.' });
    }
    const item = invRes.rows[0];
    const stock = parseInt(item.qty) || 0;
    if (loanQty > stock) {
      await dbClient.query('ROLLBACK');
      return res.status(400).json({ error: `Only ${stock} in stock.` });
    }

    const check = await dbClient.query(
      `SELECT serial_id, serial FROM inventory_serials
       WHERE serial_id = ANY($1::int[])
         AND inventory_id = $2
         AND status = 'in_stock'
       FOR UPDATE`,
      [cleanSerialIds, inventory_id]
    );
    if (check.rows.length !== loanQty) {
      await dbClient.query('ROLLBACK');
      return res.status(400).json({ error: 'One or more serials are not available.' });
    }
    const serialList = check.rows.map(r => r.serial);

    const rateNum = rate ? parseFloat(rate) : null;
    const total = rateNum ? rateNum * loanQty : null;

    const loanRes = await dbClient.query(
      `INSERT INTO loans (inventory_id, customer_name, contact_person, contact_phone, contact_email,
        part, serial, description, qty, due_date, rate, total_charge, notes, issued_by, status, serial_ids)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'active',$15)
       RETURNING *`,
      [
        inventory_id, customer_name,
        contact_person || null, contact_phone || null, contact_email || null,
        item.part, item.serial, item.description, loanQty, due_date,
        rateNum, total, notes || null, req.session.userId, cleanSerialIds
      ]
    );

    await dbClient.query(
      `UPDATE inventory_serials SET status = 'loaned'
       WHERE serial_id = ANY($1::int[])`,
      [cleanSerialIds]
    );

    await dbClient.query(
      'UPDATE inventory SET qty = qty - $1 WHERE inventory_id = $2',
      [loanQty, inventory_id]
    );

    await dbClient.query('COMMIT');

    const adminIds = await getAdminIds();
    await notify(adminIds, {
      type: 'loan_created',
      message: `New loan #${loanRes.rows[0].loan_id} to ${customer_name}: ${item.part} × ${loanQty} (due ${due_date})`,
      link: '/loans.html'
    });
    await logAudit(req, {
      entityType: 'loan', entityId: loanRes.rows[0].loan_id,
      action: 'loan.created',
      itemPart: item.part, itemSerial: serialList.join(', '), itemClient: item.client,
      inventoryId: inventory_id, loanId: loanRes.rows[0].loan_id,
      qty: loanQty, toStatus: 'active',
      notes: `Loan to ${customer_name} — due ${due_date}`
    });
    res.json(loanRes.rows[0]);
  } catch (err) {
    await dbClient.query('ROLLBACK');
    console.error('[POST /api/loans]', err);
    res.status(500).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

app.patch('/api/loans/:id/return', isAuthenticated, hasRole(['admin']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid loan ID.' });

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');
    const loanRes = await dbClient.query(
      'SELECT * FROM loans WHERE loan_id = $1 FOR UPDATE', [id]
    );
    if (loanRes.rows.length === 0) {
      await dbClient.query('ROLLBACK');
      return res.status(404).json({ error: 'Loan not found.' });
    }
    const loan = loanRes.rows[0];
    if (loan.status === 'returned') {
      await dbClient.query('ROLLBACK');
      return res.status(400).json({ error: 'Loan already returned.' });
    }

    const serialIds = Array.isArray(loan.serial_ids) && loan.serial_ids.length
      ? loan.serial_ids
      : (loan.serial_id ? [loan.serial_id] : []);

    if (serialIds.length > 0) {
      await dbClient.query(
        `UPDATE inventory_serials
         SET status = 'in_stock', removed_at = NULL, removed_by = NULL
         WHERE serial_id = ANY($1::int[]) AND status = 'loaned'`,
        [serialIds]
      );
    }

    if (loan.inventory_id) {
      await dbClient.query(
        'UPDATE inventory SET qty = qty + $1 WHERE inventory_id = $2',
        [loan.qty, loan.inventory_id]
      );
    }

    await dbClient.query(
      `UPDATE loans SET status = 'returned', returned_date = CURRENT_DATE WHERE loan_id = $1`,
      [id]
    );
    await dbClient.query('COMMIT');

    const adminIds = await getAdminIds();
    await notify(adminIds, {
      type: 'loan_returned',
      message: `Loan #${id} returned: ${loan.part} × ${loan.qty} (customer: ${loan.customer_name})`,
      link: '/loans.html'
    });
    await logAudit(req, {
      entityType: 'loan', entityId: id,
      action: 'loan.returned',
      itemPart: loan.part, itemSerial: loan.serial,
      inventoryId: loan.inventory_id, loanId: id, qty: loan.qty,
      fromStatus: 'active', toStatus: 'returned',
      notes: `Returned by ${loan.customer_name}`
    });
    res.json({ message: 'Loan returned. Inventory restored.' });
  } catch (err) {
    await dbClient.query('ROLLBACK');
    console.error('[loan return]', err);
    res.status(500).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

app.patch('/api/loans/:id/pay', isAuthenticated, hasRole(['admin', 'finance']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid loan ID.' });
  try {
    const result = await pool.query(`UPDATE loans SET payment_status = 'paid' WHERE loan_id = $1 RETURNING *`, [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Loan not found.' });
    const targets = [...new Set([...(await getAdminIds()), ...(await getFinanceIds())])];
    await notify(targets, {
      type: 'loan_paid',
      message: `Loan #${id} marked as PAID by ${req.session.fullName || 'user'}`,
      link: '/loans.html'
    });
    await logAudit(req, {
      entityType: 'loan', entityId: id,
      action: 'loan.paid',
      itemPart: result.rows[0].part, itemSerial: result.rows[0].serial,
      inventoryId: result.rows[0].inventory_id, loanId: id,
      qty: result.rows[0].qty, toStatus: 'paid', notes: 'Payment recorded'
    });
    res.json({ message: 'Payment marked as paid.', loan: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// REQUESTS ROUTES
// =============================================================
app.get('/api/requests', isAuthenticated, async (req, res) => {
  try {
    let query = `
      SELECT r.*, u1.username AS requester_name, u2.username AS approver_name,
             v.name AS vendor_name, v.email AS vendor_email, v.contact_person AS vendor_contact,
             q.price AS price, q.quotation_image_url AS quotation_image_url,
             q.delivery_estimate_days AS delivery_estimate_days,
             sc.so_number        AS so_number,
             sc.partner_customer AS so_customer,
             sc.status           AS so_status
      FROM requests r
      LEFT JOIN users u1 ON r.requested_by = u1.user_id
      LEFT JOIN users u2 ON r.approved_by = u2.user_id
      LEFT JOIN vendors v ON r.vendor_id = v.vendor_id
      LEFT JOIN so_codes sc ON r.so_code_id = sc.id
      LEFT JOIN LATERAL (
        SELECT price, quotation_image_url, delivery_estimate_days
        FROM quotations WHERE request_id = r.request_id
        ORDER BY created_at DESC LIMIT 1
      ) q ON TRUE
    `;
    if (req.session.role !== 'admin' && req.session.role !== 'manager' && req.session.role !== 'finance') {
      query += ` WHERE r.requested_by = ${req.session.userId}`;
    }
    query += ` ORDER BY r.created_at DESC`;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ⭐ Requests now accept serial_ids
app.post('/api/requests', isAuthenticated, async (req, res) => {
  const { client, category, part, serial, description, qty, rack,
          justification, priority, required_date, request_type, vendor_id, status,
          inventory_id, serial_ids } = req.body;

  if (!client || !category || !part || !qty) {
    return res.status(400).json({ error: 'Client, Category, Asset Tag, and Quantity are required.' });
  }
  if (request_type === 'external' && !vendor_id) {
    return res.status(400).json({ error: 'Please select a vendor.' });
  }
  if (request_type === 'external' && !['admin', 'manager'].includes(req.session.role)) {
    return res.status(403).json({ error: 'Only managers or admins can create external requests.' });
  }

  const isExternal = (request_type === 'external');
  const cleanSerial = isExternal ? null : (serial || null);
  const allowedStatuses = ['pending', 'approved'];
  const finalStatus = allowedStatuses.includes(status) ? status : 'pending';

  const cleanSerialIds = Array.isArray(serial_ids)
    ? serial_ids.map(x => parseInt(x)).filter(Boolean)
    : [];

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');

    if (inventory_id) {
      const invRes = await dbClient.query(
        'SELECT qty FROM inventory WHERE inventory_id = $1 FOR UPDATE', [inventory_id]
      );
      if (invRes.rows.length === 0) {
        await dbClient.query('ROLLBACK');
        return res.status(404).json({ error: 'Linked inventory item not found.' });
      }
      const stock = parseInt(invRes.rows[0].qty) || 0;
      if (qty > stock) {
        await dbClient.query('ROLLBACK');
        return res.status(400).json({ error: `Only ${stock} in stock.` });
      }

      // ⭐ Reserve specific serials if provided
      if (cleanSerialIds.length > 0) {
        if (cleanSerialIds.length !== parseInt(qty)) {
          await dbClient.query('ROLLBACK');
          return res.status(400).json({ error: 'Serial count does not match quantity.' });
        }
        const check = await dbClient.query(
          `SELECT serial_id FROM inventory_serials
           WHERE serial_id = ANY($1::int[])
             AND inventory_id = $2
             AND status = 'in_stock'`,
          [cleanSerialIds, inventory_id]
        );
        if (check.rows.length !== cleanSerialIds.length) {
          await dbClient.query('ROLLBACK');
          return res.status(400).json({ error: 'One or more serials are not available.' });
        }
        await dbClient.query(
          `UPDATE inventory_serials SET status = 'reserved'
           WHERE serial_id = ANY($1::int[])`,
          [cleanSerialIds]
        );
      }

      await dbClient.query(
        'UPDATE inventory SET qty = qty - $1 WHERE inventory_id = $2',
        [qty, inventory_id]
      );
    }

    const result = await dbClient.query(
      `INSERT INTO requests (client, category, part, serial, description, qty, rack,
        justification, priority, required_date, requested_by, status, request_type,
        vendor_id, inventory_id, serial_ids)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       RETURNING *`,
      [client, category, part, cleanSerial, description || null, qty, rack || null,
       justification || null, priority || 'medium', required_date || null,
       req.session.userId, finalStatus, request_type || 'internal',
       vendor_id || null, inventory_id || null, cleanSerialIds]
    );

    await dbClient.query('COMMIT');

    const targets = [...new Set([...(await getAdminIds()), ...(await getManagerIds())])];
    await notify(targets, {
      type: 'request_created',
      message: `New ${request_type || 'internal'} request #${result.rows[0].request_id} from ${req.session.fullName || 'user'}: ${part} × ${qty}`,
      link: '/requests.html'
    });
    await logAudit(req, {
      entityType: 'request', entityId: result.rows[0].request_id,
      action: 'request.created',
      itemPart: part, itemSerial: cleanSerial, itemClient: client,
      inventoryId: inventory_id || null, requestId: result.rows[0].request_id,
      qty, toStatus: finalStatus,
      notes: `${request_type || 'internal'} request — ${category}`
    });

    res.json(result.rows[0]);
  } catch (err) {
    await dbClient.query('ROLLBACK');
    console.error('[POST /api/requests]', err);
    res.status(500).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

app.patch('/api/requests/:id/approve', isAuthenticated, hasRole(['admin', 'manager']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid request ID.' });
  try {
    const requestResult = await pool.query(
      `SELECT r.*, v.name AS vendor_name
       FROM requests r LEFT JOIN vendors v ON r.vendor_id = v.vendor_id
       WHERE r.request_id = $1`, [id]
    );
    if (requestResult.rows.length === 0) return res.status(404).json({ error: 'Request not found.' });
    const request = requestResult.rows[0];
    if (request.status !== 'pending') return res.status(400).json({ error: `Request already ${request.status}.` });
    if (req.session.role !== 'admin' && request.requested_by === req.session.userId) return res.status(403).json({ error: 'You cannot approve your own request.' });
    await pool.query(
      `UPDATE requests SET status = 'approved', approved_by = $1, approved_at = NOW() WHERE request_id = $2`,
      [req.session.userId, id]
    );
    if (request.requested_by) {
      await notify(request.requested_by, {
        type: 'request_approved',
        message: `Your request #${id} (${request.part} × ${request.qty}) was APPROVED.`,
        link: '/requests.html'
      });
    }
    if (request.request_type === 'external') {
      const targets = [...new Set([...(await getAdminIds()), ...(await getFinanceIds())])];
      await notify(targets, {
        type: 'quotation_needed',
        message: `External request #${id} (${request.part} × ${request.qty}) approved — upload quotation for ${request.vendor_name || 'vendor'}.`,
        link: '/finance.html'
      });
    }
    await logAudit(req, {
      entityType: 'request', entityId: id,
      action: 'request.approved',
      itemPart: request.part, itemSerial: request.serial, itemClient: request.client,
      inventoryId: request.inventory_id, requestId: id,
      qty: request.qty, fromStatus: 'pending', toStatus: 'approved',
      notes: request.vendor_name ? `Vendor: ${request.vendor_name}` : null
    });
    res.json({ message: 'Request approved.', request: { ...request, status: 'approved' } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ⭐ Reject restores serials to in_stock
app.patch('/api/requests/:id/reject', isAuthenticated, hasRole(['admin', 'manager']), async (req, res) => {
  const id = parseInt(req.params.id);
  const { reason } = req.body;
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid request ID.' });

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');
    const requestResult = await dbClient.query(
      'SELECT * FROM requests WHERE request_id = $1 FOR UPDATE', [id]
    );
    if (requestResult.rows.length === 0) {
      await dbClient.query('ROLLBACK');
      return res.status(404).json({ error: 'Request not found.' });
    }
    const request = requestResult.rows[0];
    if (request.status !== 'pending') {
      await dbClient.query('ROLLBACK');
      return res.status(400).json({ error: `Request already ${request.status}.` });
    }

    // ⭐ Restore reserved serials back to in_stock
    const serialIds = Array.isArray(request.serial_ids) ? request.serial_ids : [];
    if (serialIds.length > 0) {
      await dbClient.query(
        `UPDATE inventory_serials SET status = 'in_stock'
         WHERE serial_id = ANY($1::int[]) AND status = 'reserved'`,
        [serialIds]
      );
    }

    if (request.inventory_id) {
      await dbClient.query(
        'UPDATE inventory SET qty = qty + $1 WHERE inventory_id = $2',
        [request.qty, request.inventory_id]
      );
    }

    await dbClient.query(
      `UPDATE requests SET status = 'rejected', approved_by = $1, approved_at = NOW(),
        rejected_reason = $2 WHERE request_id = $3`,
      [req.session.userId, reason || 'No reason provided.', id]
    );
    await dbClient.query('COMMIT');

    if (request.requested_by) {
      await notify(request.requested_by, {
        type: 'request_rejected',
        message: `Your request #${id} (${request.part}) was REJECTED: ${reason || 'No reason provided.'}`,
        link: '/requests.html'
      });
    }
    await logAudit(req, {
      entityType: 'request', entityId: id,
      action: 'request.rejected',
      itemPart: request.part, itemSerial: request.serial, itemClient: request.client,
      inventoryId: request.inventory_id, requestId: id,
      qty: request.qty, fromStatus: 'pending', toStatus: 'rejected',
      notes: reason || 'No reason provided.'
    });
    res.json({ message: 'Request rejected.', request: { ...request, status: 'rejected' } });
  } catch (err) {
    await dbClient.query('ROLLBACK');
    console.error('[reject]', err);
    res.status(500).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

app.patch('/api/requests/:id/status', isAuthenticated, hasRole(['admin', 'finance', 'manager']), async (req, res) => {
  const id = parseInt(req.params.id);
  const { status, tracking_number } = req.body;
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid request ID.' });
  if (!status) return res.status(400).json({ error: 'Status is required.' });
  try {
    const before = await pool.query(
      'SELECT status, part, serial, client, qty, inventory_id, tracking_number FROM requests WHERE request_id = $1',
      [id]
    );
    if (before.rows.length === 0) return res.status(404).json({ error: 'Request not found.' });

    // If tracking_number is provided (even empty string → clear), include it
    let query, params;
    if (tracking_number !== undefined) {
      query = `UPDATE requests SET status = $1, tracking_number = $2 WHERE request_id = $3 RETURNING *`;
      params = [status, (tracking_number || '').toString().trim() || null, id];
    } else {
      query = `UPDATE requests SET status = $1 WHERE request_id = $2 RETURNING *`;
      params = [status, id];
    }

    const result = await pool.query(query, params);
    const reqRow = result.rows[0];
    const oldStatus = before.rows[0].status || null;
    const oldTracking = before.rows[0].tracking_number || null;
    const newTracking = reqRow.tracking_number || null;

    let notes = null;
    if (oldTracking !== newTracking) {
      notes = `Tracking: ${oldTracking || '—'} → ${newTracking || '—'}`;
    }

    await logAudit(req, {
      entityType: 'request', entityId: id,
      action: 'request.status_changed',
      itemPart: reqRow.part, itemSerial: reqRow.serial, itemClient: reqRow.client,
      inventoryId: reqRow.inventory_id, requestId: id,
      qty: reqRow.qty, fromStatus: oldStatus, toStatus: status,
      notes
    });

    res.json({ message: `Status updated to ${status}.`, request: reqRow });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/requests/:id/manager-decision', isAuthenticated, hasRole(['admin', 'manager']), async (req, res) => {
  const id = parseInt(req.params.id);
  const { decision, reason } = req.body;
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid request ID.' });
  if (!['approve', 'reject'].includes(decision)) return res.status(400).json({ error: 'Decision must be "approve" or "reject".' });
  try {
    let result;
    if (decision === 'approve') {
      result = await pool.query(`UPDATE requests SET status = 'pending_purchase', approved_by = $1, approved_at = NOW() WHERE request_id = $2 RETURNING *`, [req.session.userId, id]);
    } else {
      result = await pool.query(`UPDATE requests SET status = 'rejected', approved_by = $1, approved_at = NOW(), rejected_reason = $2 WHERE request_id = $3 RETURNING *`, [req.session.userId, reason || 'No reason provided.', id]);
    }
    if (result.rows.length === 0) return res.status(404).json({ error: 'Request not found.' });
    const reqRow = result.rows[0];
    const targets = [...new Set([...(await getAdminIds()), ...(await getFinanceIds()), reqRow.requested_by].filter(Boolean))];
    const msg = decision === 'approve'
      ? `Request #${id} (${reqRow.part}) quotation APPROVED by ${req.session.fullName || 'a manager'} — proceeding to purchase.`
      : `Request #${id} (${reqRow.part}) quotation REJECTED by ${req.session.fullName || 'a manager'}.`;
    await notify(targets, {
      type: decision === 'approve' ? 'quotation_approved' : 'quotation_rejected',
      message: msg, link: '/finance.html'
    });
    await logAudit(req, {
      entityType: 'request', entityId: id,
      action: decision === 'approve' ? 'request.quotation_approved' : 'request.quotation_rejected',
      itemPart: reqRow.part, itemSerial: reqRow.serial, itemClient: reqRow.client,
      inventoryId: reqRow.inventory_id, requestId: id, qty: reqRow.qty,
      fromStatus: 'pending_manager_approval',
      toStatus: decision === 'approve' ? 'pending_purchase' : 'rejected',
      notes: reason || null
    });
    res.json({ message: `Request #${id} ${decision}d.`, request: reqRow });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ⭐ User-confirm marks serials taken_out
app.patch('/api/requests/:id/user-confirm', isAuthenticated, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid request ID.' });
  try {
    const r = await pool.query('SELECT * FROM requests WHERE request_id = $1', [id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Request not found.' });
    const request = r.rows[0];

    if (req.session.role !== 'admin' && request.requested_by !== req.session.userId) {
      return res.status(403).json({ error: 'Only the requester can confirm.' });
    }
    if (request.status !== 'delivered') {
      return res.status(400).json({ error: `Request is "${request.status}".` });
    }

    // ⭐ Serial stays "reserved" while on-site; becomes "taken_out" once user confirms
    const serialIds = Array.isArray(request.serial_ids) ? request.serial_ids : [];
    if (serialIds.length > 0) {
      await pool.query(
        `UPDATE inventory_serials SET status = 'taken_out', removed_at = NOW(), removed_by = $1
         WHERE serial_id = ANY($2::int[]) AND status = 'reserved'`,
        [req.session.userId, serialIds]
      );
    }

    const result = await pool.query(
      `UPDATE requests SET status = 'completed' WHERE request_id = $1 RETURNING *`, [id]
    );

    const targets = [...new Set([...(await getAdminIds()), ...(await getFinanceIds())])];
    await notify(targets, {
      type: 'request_completed',
      message: `Request #${id} (${request.part}) COMPLETED — user confirmed receipt.`,
      link: '/finance.html'
    });
    await logAudit(req, {
      entityType: 'request', entityId: id,
      action: 'request.completed',
      itemPart: request.part, itemSerial: request.serial, itemClient: request.client,
      inventoryId: request.inventory_id, requestId: id, qty: request.qty,
      fromStatus: 'delivered', toStatus: 'completed'
    });
    res.json({ message: 'Receipt confirmed.', request: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// EMAIL ROUTES
// =============================================================
app.get('/api/emails/threads', isAuthenticated, hasRole(['admin', 'finance', 'manager']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        r.request_id, r.part, r.category, r.qty, r.client, r.status, r.created_at,
        v.name  AS vendor_name,
        v.email AS vendor_email,
        u.username AS requester_name,
        (SELECT COUNT(*)::int FROM email_log e WHERE e.request_id = r.request_id AND e.direction='sent')     AS sent_count,
        (SELECT COUNT(*)::int FROM email_log e WHERE e.request_id = r.request_id AND e.direction='received') AS received_count,
        (SELECT COUNT(*)::int FROM email_log e WHERE e.request_id = r.request_id AND e.direction='received' AND e.is_read = FALSE) AS unread_count,
        (SELECT MAX(created_at) FROM email_log e WHERE e.request_id = r.request_id) AS last_activity
      FROM requests r
      LEFT JOIN vendors v ON r.vendor_id = v.vendor_id
      LEFT JOIN users u ON r.requested_by = u.user_id
      WHERE r.request_type = 'external'
        AND r.vendor_id IS NOT NULL
      ORDER BY
        (SELECT COUNT(*) FROM email_log e WHERE e.request_id = r.request_id AND e.direction='received' AND e.is_read = FALSE) DESC,
        r.created_at DESC
      LIMIT 200
    `);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/emails/thread/:requestId', isAuthenticated, hasRole(['admin', 'finance', 'manager']), async (req, res) => {
  const requestId = parseInt(req.params.requestId);
  if (isNaN(requestId)) return res.status(400).json({ error: 'Invalid request ID.' });
  try {
    const reqInfo = await pool.query(`
      SELECT r.*, v.name AS vendor_name, v.email AS vendor_email, v.contact_person AS vendor_contact,
             u.username AS requester_name
      FROM requests r
      LEFT JOIN vendors v ON r.vendor_id = v.vendor_id
      LEFT JOIN users u ON r.requested_by = u.user_id
      WHERE r.request_id = $1
    `, [requestId]);
    if (reqInfo.rows.length === 0) return res.status(404).json({ error: 'Request not found.' });

    const emails = await pool.query(`
      SELECT email_id, direction, from_email, to_email, subject,
             body_preview, body_full, attachments, user_name, is_read, created_at
      FROM email_log
      WHERE request_id = $1
      ORDER BY created_at ASC
    `, [requestId]);

    res.json({
      request: reqInfo.rows[0],
      emails: emails.rows
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/emails/send',
  isAuthenticated,
  hasRole(['admin', 'finance']),
  emailUpload.array('attachments', 5),
  async (req, res) => {
    const { request_id, to, subject, body } = req.body;
    if (!request_id || !to || !subject || !body) {
      return res.status(400).json({ error: 'request_id, to, subject, and body are required.' });
    }

    const requestId = parseInt(request_id);
    if (isNaN(requestId)) return res.status(400).json({ error: 'Invalid request_id.' });

    try {
      const check = await pool.query(
        'SELECT r.request_id, r.part FROM requests r WHERE r.request_id = $1',
        [requestId]
      );
      if (check.rows.length === 0) return res.status(404).json({ error: 'Request not found.' });

      let finalSubject = subject.trim();
      const tag = `[REQ-${requestId}]`;
      if (!finalSubject.includes(tag)) finalSubject = `${tag} ${finalSubject}`;

      const attachments = (req.files || []).map(f => ({
        filename: f.originalname,
        path: f.path,
        contentType: f.mimetype
      }));

      const info = await emailTransporter.sendMail({
        from: EMAIL_FROM,
        to,
        subject: finalSubject,
        text: body,
        attachments
      });

      const storedAttachments = attachments.map(a => ({
        filename: a.filename,
        stored: `/uploads/emails/${path.basename(a.path)}`,
        size: fs.existsSync(a.path) ? fs.statSync(a.path).size : 0,
        mimetype: a.contentType
      }));

      await pool.query(
        `INSERT INTO email_log
          (request_id, direction, from_email, to_email, subject,
           body_preview, body_full, message_id, attachments, user_id, user_name, is_read)
         VALUES ($1,'sent',$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,TRUE)`,
        [
          requestId,
          SMTP_USER,
          to,
          finalSubject,
          makePreview(body),
          body.slice(0, 50000),
          info.messageId || null,
          JSON.stringify(storedAttachments),
          req.session.userId,
          req.session.fullName || 'User'
        ]
      );

      await logAudit(req, {
        entityType: 'request',
        entityId: requestId,
        action: 'email.sent',
        requestId,
        notes: `To: ${to} — ${finalSubject}`
      });

      res.json({ message: `Email sent to ${to}`, messageId: info.messageId });
    } catch (err) {
      console.error('Email send failed:', err);
      res.status(500).json({ error: err.message });
    }
  }
);

app.post('/api/emails/sync', isAuthenticated, hasRole(['admin', 'finance', 'manager']), async (req, res) => {
  try {
    const summary = await syncInbox({ force: true });
    res.json({ message: 'Sync complete.', ...summary });
  } catch (err) {
    console.error('Sync error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/emails/:id/read', isAuthenticated, hasRole(['admin', 'finance', 'manager']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid email ID.' });
  try {
    const result = await pool.query(
      'UPDATE email_log SET is_read = TRUE WHERE email_id = $1 RETURNING *',
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not found.' });
    res.json({ message: 'Marked as read.', email: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/emails/unread-count', isAuthenticated, hasRole(['admin', 'finance', 'manager']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT COUNT(*)::int AS count FROM email_log
       WHERE direction = 'received'
         AND is_read = FALSE
         AND request_id IS NOT NULL`
    );
    res.json({ count: result.rows[0].count });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// LEGACY
// =============================================================
app.post('/api/requests/:id/send-quotation-email', isAuthenticated, hasRole(['admin', 'finance']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid request ID.' });
  const { recipient, subject, body } = req.body;
  if (!recipient || !subject || !body) return res.status(400).json({ error: 'Recipient, subject, and body are required.' });
  try {
    const check = await pool.query('SELECT request_id FROM requests WHERE request_id = $1', [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Request not found.' });
    await emailTransporter.sendMail({ from: EMAIL_FROM, to: recipient, subject, text: body });
    res.json({ message: `Email sent to ${recipient}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// CLIENTS
// =============================================================
app.get('/api/clients', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT client FROM inventory
       WHERE client IS NOT NULL AND TRIM(client) <> ''
       ORDER BY client`
    );
    res.json(result.rows.map(r => r.client));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// AUDIT LOG ROUTES
// =============================================================
app.get('/api/audit', isAuthenticated, async (req, res) => {
  try {
    if (!['admin', 'manager', 'finance'].includes(req.session.role)) {
      return res.status(403).json({ error: 'Insufficient permissions.' });
    }
    const { entity_type, action, user_id, inventory_id, serial, part, from, to, limit } = req.query;
    const conditions = [];
    const values = [];
    let i = 1;
    if (entity_type)  { conditions.push(`entity_type = $${i++}`);  values.push(entity_type); }
    if (action)       { conditions.push(`action = $${i++}`);       values.push(action); }
    if (user_id)      { conditions.push(`user_id = $${i++}`);      values.push(parseInt(user_id)); }
    if (inventory_id) { conditions.push(`inventory_id = $${i++}`); values.push(parseInt(inventory_id)); }
    if (serial)       { conditions.push(`item_serial ILIKE $${i++}`); values.push(`%${serial}%`); }
    if (part)         { conditions.push(`item_part ILIKE $${i++}`);   values.push(`%${part}%`); }
    if (from)         { conditions.push(`created_at >= $${i++}`); values.push(from); }
    if (to)           { conditions.push(`created_at <= $${i++}`); values.push(to); }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const lim = Math.min(parseInt(limit) || 200, 500);
    const result = await pool.query(
      `SELECT * FROM audit_log ${where} ORDER BY created_at DESC LIMIT ${lim}`,
      values
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/audit/actions', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(`SELECT DISTINCT action FROM audit_log ORDER BY action`);
    res.json(result.rows.map(r => r.action));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// VENDOR
// =============================================================
app.get('/api/vendors', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM vendors ORDER BY name');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/vendors', isAuthenticated, hasRole(['admin', 'manager', 'finance']), async (req, res) => {
  const { name, contact_person, email, phone, performance_rating } = req.body;
  if (!name || !contact_person || !email || !phone) {
    return res.status(400).json({ error: 'Name, contact person, email, and phone are required.' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO vendors (name, contact_person, email, phone, performance_rating)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [name, contact_person, email, phone, performance_rating || null]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// QUOTATIONS
// =============================================================
app.get('/api/quotations/request/:requestId', isAuthenticated, async (req, res) => {
  const requestId = parseInt(req.params.requestId);
  if (isNaN(requestId)) return res.status(400).json({ error: 'Invalid request ID.' });
  try {
    const result = await pool.query(
      `SELECT q.*, v.name as vendor_name FROM quotations q
       JOIN vendors v ON q.vendor_id = v.vendor_id
       WHERE q.request_id = $1 ORDER BY q.price ASC`, [requestId]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/quotations', isAuthenticated, hasRole(['admin', 'finance']), upload.single('quotation_image'), async (req, res) => {
  const { request_id, vendor_id, price, delivery_estimate_days, valid_until, notes, so_code_id } = req.body;

  if (!request_id || !vendor_id || !price) {
    return res.status(400).json({ error: 'Request ID, Vendor ID, and Price are required.' });
  }
  if (!req.file) {
    return res.status(400).json({ error: 'Quotation file is required.' });
  }

  const quotation_image_url = `/uploads/quotations/${req.file.filename}`;
  const cleanSoCodeId = so_code_id && String(so_code_id).trim() ? String(so_code_id).trim() : null;

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');

    // ⭐ Validate SO Code if provided
    let soCodeLabel = null;
    if (cleanSoCodeId) {
      const soCheck = await dbClient.query(
        `SELECT id, so_number, partner_customer, status FROM so_codes WHERE id = $1`,
        [cleanSoCodeId]
      );
      if (soCheck.rows.length === 0) {
        await dbClient.query('ROLLBACK');
        return res.status(400).json({ error: 'Selected SO Code not found.' });
      }
      const so = soCheck.rows[0];
      if (so.status !== 'OPEN') {
        await dbClient.query('ROLLBACK');
        return res.status(400).json({
          error: `SO Code ${so.so_number || so.id} is "${so.status}" — only OPEN codes can be used.`
        });
      }
      soCodeLabel = `${so.so_number || so.id} — ${so.partner_customer || '—'}`;
    }

    // Insert quotation
    const result = await dbClient.query(
      `INSERT INTO quotations (request_id, vendor_id, price, delivery_estimate_days, valid_until, notes, quotation_image_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [request_id, vendor_id, price, delivery_estimate_days || null, valid_until || null, notes || null, quotation_image_url]
    );

    // ⭐ Save SO Code on the request + move status
    await dbClient.query(
      `UPDATE requests SET status = 'pending_manager_approval', so_code_id = $1
       WHERE request_id = $2`,
      [cleanSoCodeId, request_id]
    );

    await dbClient.query('COMMIT');

    // Notifications
    const reqInfo = await pool.query(
      'SELECT part, serial, client, qty, inventory_id FROM requests WHERE request_id = $1',
      [request_id]
    );
    const r = reqInfo.rows[0] || {};
    const targets = [...new Set([...(await getAdminIds()), ...(await getManagerIds())])];
    await notify(targets, {
      type: 'quotation_uploaded',
      message: `Quotation uploaded for request #${request_id} — RM ${price}${soCodeLabel ? ` · SO: ${soCodeLabel}` : ''}. Waiting for manager approval.`,
      link: '/finance.html'
    });

    await logAudit(req, {
      entityType: 'quotation',
      entityId: result.rows[0].quotation_id,
      action: 'quotation.uploaded',
      itemPart: r.part, itemSerial: r.serial, itemClient: r.client,
      inventoryId: r.inventory_id, requestId: request_id, qty: r.qty,
      fromStatus: 'approved', toStatus: 'pending_manager_approval',
      notes: `RM ${price}${soCodeLabel ? ` — SO: ${soCodeLabel}` : ' — no SO code'}`
    });

    res.json(result.rows[0]);
  } catch (err) {
    await dbClient.query('ROLLBACK');
    console.error('[POST /api/quotations]', err);
    res.status(500).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

// =============================================================
// SO CODES — WMS routes
// =============================================================

// Manual trigger — admin only
app.post('/api/admin/sync-so-codes', isAuthenticated, hasRole(['admin']), async (req, res) => {
  try {
    const stats = await syncSOCodes();
    res.json({ message: 'Sync complete.', ...stats });
  } catch (err) {
    console.error('[sync-so-codes]', err);
    res.status(500).json({ error: err.message });
  }
});

// List cached SO Codes (any authenticated user)
app.get('/api/so-codes', isAuthenticated, async (req, res) => {
  const { status, q, limit, offset } = req.query;
  const conds = [];
  const values = [];
  let i = 1;

  if (status) {
    conds.push(`status = $${i++}`);
    values.push(status);
  }
  if (q) {
    conds.push(`(so_number ILIKE $${i} OR partner_customer ILIKE $${i} OR description ILIKE $${i})`);
    values.push(`%${q}%`);
    i++;
  }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const lim = Math.min(parseInt(limit) || 100, 500);
  const off = Math.max(parseInt(offset) || 0, 0);

  try {
    const [rows, countRes, metaRes] = await Promise.all([
      pool.query(
        `SELECT * FROM so_codes ${where}
         ORDER BY exa_updated_at DESC NULLS LAST, so_number DESC
         LIMIT ${lim} OFFSET ${off}`,
        values
      ),
      pool.query(`SELECT COUNT(*)::int AS total FROM so_codes ${where}`, values),
      pool.query(`SELECT MAX(last_synced_at) AS last_sync FROM so_codes`)
    ]);

    res.json({
      items: rows.rows,
      total: countRes.rows[0].total,
      last_sync: metaRes.rows[0].last_sync
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Distinct statuses for the filter dropdown
app.get('/api/so-codes/statuses', isAuthenticated, async (req, res) => {
  try {
    const r = await pool.query(`SELECT DISTINCT status FROM so_codes WHERE status IS NOT NULL ORDER BY status`);
    res.json(r.rows.map(x => x.status));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/quotations/:id/accept', isAuthenticated, hasRole(['admin', 'finance']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid quotation ID.' });
  try {
    const quoteResult = await pool.query('SELECT * FROM quotations WHERE quotation_id = $1', [id]);
    if (quoteResult.rows.length === 0) return res.status(404).json({ error: 'Quotation not found.' });
    const quote = quoteResult.rows[0];
    const requestResult = await pool.query('SELECT * FROM requests WHERE request_id = $1', [quote.request_id]);
    if (requestResult.rows.length === 0) return res.status(404).json({ error: 'Request not found.' });
    const request = requestResult.rows[0];
    const timestamp = Date.now().toString().slice(-6);
    const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
    const po_number = `PO-${timestamp}-${random}`;
    const poResult = await pool.query(
      `INSERT INTO purchase_orders (po_number, request_id, vendor_id, quotation_id, total_amount, expected_delivery)
       VALUES ($1, $2, $3, $4, $5, NOW() + ($6 || ' days')::INTERVAL) RETURNING *`,
      [po_number, request.request_id, quote.vendor_id, quote.quotation_id, quote.price, quote.delivery_estimate_days || 7]
    );
    await pool.query('UPDATE quotations SET status = $1 WHERE quotation_id = $2', ['accepted', id]);
    await pool.query('UPDATE requests SET status = $1 WHERE request_id = $2', ['ordered', request.request_id]);
    await logAudit(req, {
      entityType: 'po', entityId: poResult.rows[0].po_id,
      action: 'po.created',
      itemPart: request.part, itemSerial: request.serial, itemClient: request.client,
      inventoryId: request.inventory_id, requestId: request.request_id, qty: request.qty,
      toStatus: 'ordered', notes: `PO ${po_number} — RM ${quote.price}`
    });
    res.json({ message: `PO ${po_number} created.`, purchase_order: poResult.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// PURCHASE ORDERS
// =============================================================
app.get('/api/purchase-orders', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT po.*, v.name as vendor_name, r.part as request_part, u.username as requested_by
       FROM purchase_orders po
       JOIN vendors v ON po.vendor_id = v.vendor_id
       JOIN requests r ON po.request_id = r.request_id
       LEFT JOIN users u ON r.requested_by = u.user_id
       ORDER BY po.issued_at DESC`
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/purchase-orders/:id/status', isAuthenticated, hasRole(['admin', 'finance']), async (req, res) => {
  const id = parseInt(req.params.id);
  const { status } = req.body;
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid PO ID.' });
  if (!status) return res.status(400).json({ error: 'Status is required.' });
  try {
    const result = await pool.query(
      `UPDATE purchase_orders SET status = $1, delivered_at = CASE WHEN $1 = 'received' THEN NOW() ELSE delivered_at END
       WHERE po_id = $2 RETURNING *`, [status, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'PO not found.' });
    res.json({ message: `PO status updated to ${status}.`, purchase_order: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/purchase-orders/:id/receive', isAuthenticated, hasRole(['admin', 'technician']), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid PO ID.' });

  const { client, rack, serials } = req.body;

  if (!client || !rack) {
    return res.status(400).json({ error: 'Client and rack are required.' });
  }
  if (!Array.isArray(serials) || serials.length === 0) {
    return res.status(400).json({ error: 'Serial numbers are required.' });
  }
  const cleanSerials = serials.map(s => String(s || '').trim()).filter(Boolean);
  if (cleanSerials.length !== serials.length) {
    return res.status(400).json({ error: 'All serial number fields must be filled.' });
  }
  const dup = cleanSerials.filter((s, i) => cleanSerials.indexOf(s) !== i);
  if (dup.length) {
    return res.status(400).json({ error: `Duplicate serial in submission: ${dup[0]}` });
  }

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');

    const poRes = await dbClient.query(
      'SELECT * FROM purchase_orders WHERE po_id = $1 FOR UPDATE', [id]
    );
    if (poRes.rows.length === 0) {
      await dbClient.query('ROLLBACK');
      return res.status(404).json({ error: 'Purchase Order not found.' });
    }
    const po = poRes.rows[0];
    if (po.status === 'received') {
      await dbClient.query('ROLLBACK');
      return res.status(400).json({ error: 'PO already received.' });
    }

    const reqRes = await dbClient.query(
      'SELECT * FROM requests WHERE request_id = $1', [po.request_id]
    );
    if (reqRes.rows.length === 0) {
      await dbClient.query('ROLLBACK');
      return res.status(404).json({ error: 'Linked request not found.' });
    }
    const reqRow = reqRes.rows[0];

    const conflict = await dbClient.query(
      `SELECT serial FROM inventory_serials WHERE serial = ANY($1::text[])`,
      [cleanSerials]
    );
    if (conflict.rows.length > 0) {
      await dbClient.query('ROLLBACK');
      return res.status(400).json({
        error: `Serial already in system: ${conflict.rows.map(r => r.serial).join(', ')}`
      });
    }

    const finalQty = cleanSerials.length;

    const existing = await dbClient.query(
      `SELECT * FROM inventory
       WHERE category = $1 AND part = $2 AND client = $3 AND rack = $4
       FOR UPDATE`,
      [reqRow.category, reqRow.part, client, rack]
    );

        // ⭐ Validate SO Code if provided (must exist + be OPEN)
    let soCodeLabel = null;
    if (cleanSoCodeId) {
      const soCheck = await dbClient.query(
        `SELECT id, so_number, partner_customer, status FROM so_codes WHERE id = $1`,
        [cleanSoCodeId]
      );
      if (soCheck.rows.length === 0) {
        await dbClient.query('ROLLBACK');
        return res.status(400).json({ error: 'Selected SO Code not found.' });
      }
      const so = soCheck.rows[0];
      if (so.status !== 'OPEN') {
        await dbClient.query('ROLLBACK');
        return res.status(400).json({
          error: `SO Code ${so.so_number || so.id} is "${so.status}" — only OPEN codes can be used.`
        });
      }
      soCodeLabel = `${so.so_number || so.id} — ${so.partner_customer || '—'}`;
    }

    let invRow;
    if (existing.rows.length > 0) {
      invRow = existing.rows[0];
      // ⭐ If new SO code provided, use it; otherwise keep existing
      const newSoCode = cleanSoCodeId || invRow.so_code_id;
      const upd = await dbClient.query(
        `UPDATE inventory SET qty = qty + $1, so_code_id = $2 WHERE inventory_id = $3 RETURNING *`,
        [finalQty, newSoCode, invRow.inventory_id]
      );
      invRow = upd.rows[0];
    } else {
      const ins = await dbClient.query(
        `INSERT INTO inventory (client, category, part, serial, description, qty, rack, so_code_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
        [client, category, part, cleanSerials[0], description, finalQty, rack, cleanSoCodeId]
      );
      invRow = ins.rows[0];
    }

    const vals = [];
    const params = [];
    cleanSerials.forEach((s, i) => {
      const b = i * 3;
      vals.push(`($${b + 1}, $${b + 2}, $${b + 3})`);
      params.push(invRow.inventory_id, s, req.session.userId);
    });
    await dbClient.query(
      `INSERT INTO inventory_serials (inventory_id, serial, added_by)
       VALUES ${vals.join(', ')}`,
      params
    );

    const poUpd = await dbClient.query(
      `UPDATE purchase_orders SET status = 'received', received_at = NOW()
       WHERE po_id = $1 RETURNING *`,
      [id]
    );
    await dbClient.query(
      `UPDATE requests SET status = 'delivered' WHERE request_id = $1`,
      [po.request_id]
    );

    await dbClient.query('COMMIT');

    const targets = [...new Set([
      ...(await getAdminIds()),
      ...(await getFinanceIds()),
      reqRow.requested_by
    ].filter(Boolean))];
    await notify(targets, {
      type: 'request_completed',
      message: `PO ${po.po_number} received — ${reqRow.part} × ${finalQty} added to inventory at ${client} (Rack ${rack}).`,
      link: '/inventory.html'
    });
    await logAudit(req, {
      entityType: 'po',
      entityId: id,
      action: 'po.received',
      itemPart: reqRow.part,
      itemSerial: cleanSerials.join(', '),
      itemClient: client,
      inventoryId: invRow.inventory_id,
      requestId: po.request_id,
      qty: finalQty,
      fromStatus: po.status,
      toStatus: 'received',
      notes: `PO ${po.po_number} received → added to inventory (Rack ${rack})`
    });

    res.json({
      message: `PO ${po.po_number} received. ${finalQty} unit(s) added to inventory.`,
      purchase_order: poUpd.rows[0],
      inventory: invRow
    });
  } catch (err) {
    await dbClient.query('ROLLBACK');
    console.error('[po receive]', err);
    res.status(500).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

// =============================================================
// REPORTS ROUTES
// =============================================================
function isReportViewer(req, res, next) {
  if (['admin', 'manager', 'finance'].includes(req.session.role)) return next();
  res.status(403).json({ error: 'Insufficient permissions.' });
}

app.get('/api/reports/overview', isAuthenticated, isReportViewer, async (req, res) => {
  try {
    const [inv, loans, reqs, byCategory, reqsByStatus, loansSummary] = await Promise.all([
      pool.query(`SELECT
        COUNT(*) FILTER (WHERE qty > 0)::int              AS items,
        COALESCE(SUM(qty), 0)::int                        AS units,
        COUNT(DISTINCT client) FILTER (WHERE client IS NOT NULL AND TRIM(client) <> '')::int AS clients,
        COUNT(DISTINCT category) FILTER (WHERE category IS NOT NULL)::int AS categories,
        COUNT(*) FILTER (WHERE qty > 0 AND qty <= 5)::int AS low_stock
        FROM inventory`),
      pool.query(`SELECT
        COUNT(*) FILTER (WHERE status = 'active')::int                          AS active,
        COUNT(*) FILTER (WHERE status = 'active' AND due_date < CURRENT_DATE)::int AS overdue,
        COUNT(*) FILTER (WHERE status = 'returned')::int                        AS returned
        FROM loans`),
      pool.query(`SELECT
        COUNT(*)::int                                          AS total,
        COUNT(*) FILTER (WHERE status = 'pending')::int        AS pending,
        COUNT(*) FILTER (WHERE status = 'approved')::int       AS approved,
        COUNT(*) FILTER (WHERE status = 'rejected')::int       AS rejected,
        COUNT(*) FILTER (WHERE status = 'completed')::int      AS completed,
        COUNT(*) FILTER (WHERE request_type = 'external')::int AS external,
        COUNT(*) FILTER (WHERE request_type = 'internal')::int AS internal
        FROM requests`),
      pool.query(`SELECT category, COALESCE(SUM(qty), 0)::int AS units
        FROM inventory
        WHERE qty > 0 AND category IS NOT NULL
        GROUP BY category ORDER BY units DESC`),
      pool.query(`SELECT status, COUNT(*)::int AS count
        FROM requests GROUP BY status ORDER BY count DESC`),
      pool.query(`SELECT
        COUNT(*)::int AS total,
        COALESCE(SUM(total_charge), 0)::float AS revenue
        FROM loans WHERE status = 'active'`)
    ]);

    res.json({
      inventory:            inv.rows[0],
      loans:                loans.rows[0],
      requests:             reqs.rows[0],
      inventory_by_category: byCategory.rows,
      requests_by_status:   reqsByStatus.rows,
      loans_summary:        loansSummary.rows[0]
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reports/inventory', isAuthenticated, isReportViewer, async (req, res) => {
  const { client, category, from, to } = req.query;
  const conds = [];
  const values = [];
  let i = 1;
  if (client)   { conds.push(`client = $${i++}`);   values.push(client); }
  if (category) { conds.push(`category = $${i++}`); values.push(category); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';

  // Decomposed query (uses serials table, own filter on removed_at)
  const decoConds = [`s.status = 'taken_out'`];
  const decoValues = [];
  let j = 1;
  if (client)   { decoConds.push(`inv.client = $${j++}`);   decoValues.push(client); }
  if (category) { decoConds.push(`inv.category = $${j++}`); decoValues.push(category); }
  if (from)     { decoConds.push(`s.removed_at >= $${j++}`); decoValues.push(from); }
  if (to)       { decoConds.push(`s.removed_at <= $${j++}`); decoValues.push(to); }
  const decoWhere = `WHERE ${decoConds.join(' AND ')}`;

  try {
    const [totals, byCategory, byClient, lowStock, decomposedList, decomposedCount] = await Promise.all([
      pool.query(`SELECT
        COUNT(*)::int                              AS items,
        COALESCE(SUM(qty), 0)::int                 AS units,
        COUNT(DISTINCT client)::int                AS clients,
        COUNT(DISTINCT category)::int              AS categories,
        COUNT(*) FILTER (WHERE qty <= 5)::int      AS low_stock
        FROM inventory ${where}`, values),

      pool.query(`SELECT category,
        COUNT(*)::int                              AS items,
        COALESCE(SUM(qty), 0)::int                 AS units,
        COUNT(DISTINCT client)::int                AS clients,
        COUNT(*) FILTER (WHERE qty <= 5)::int      AS low_stock
        FROM inventory ${where}
        GROUP BY category ORDER BY units DESC`, values),

      pool.query(`SELECT client,
        COUNT(*)::int                              AS items,
        COALESCE(SUM(qty), 0)::int                 AS units,
        COUNT(DISTINCT category)::int              AS categories
        FROM inventory ${where}
        GROUP BY client ORDER BY units DESC`, values),

      pool.query(`SELECT inventory_id, client, category, part, serial, description, qty, rack
        FROM inventory WHERE qty > 0 AND qty <= 5
        ORDER BY qty ASC, part ASC LIMIT 30`),

      // ⭐ NEW — list of decomposed units
      pool.query(`SELECT
          s.serial_id, s.serial, s.removed_at,
          inv.inventory_id, inv.client, inv.category, inv.part, inv.description, inv.rack, inv.so_code_id,
          u.username AS removed_by_name,
          sc.so_number AS so_number
        FROM inventory_serials s
        LEFT JOIN inventory inv ON s.inventory_id = inv.inventory_id
        LEFT JOIN users u ON s.removed_by = u.user_id
        LEFT JOIN so_codes sc ON inv.so_code_id = sc.id
        ${decoWhere}
        ORDER BY s.removed_at DESC NULLS LAST
        LIMIT 200`, decoValues),

      // ⭐ NEW — count for stat card
      pool.query(`SELECT COUNT(*)::int AS c
        FROM inventory_serials s
        LEFT JOIN inventory inv ON s.inventory_id = inv.inventory_id
        ${decoWhere}`, decoValues)
    ]);

    res.json({
      totals: {
        ...totals.rows[0],
        decomposed: decomposedCount.rows[0].c    // ⭐ merged into totals
      },
      by_category: totals ? byCategory.rows : [],
      by_client:   byClient.rows,
      low_stock:   lowStock.rows,
      decomposed:  decomposedList.rows           // ⭐ the list
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reports/requests', isAuthenticated, isReportViewer, async (req, res) => {
  const { from, to, client, category, request_type, status } = req.query;
  const conds = [];
  const values = [];
  let i = 1;
  if (from)         { conds.push(`r.created_at >= $${i++}`);   values.push(from); }
  if (to)           { conds.push(`r.created_at <= $${i++}`);   values.push(to); }
  if (client)       { conds.push(`r.client = $${i++}`);        values.push(client); }
  if (category)     { conds.push(`r.category = $${i++}`);      values.push(category); }
  if (request_type) { conds.push(`r.request_type = $${i++}`);  values.push(request_type); }
  if (status)       { conds.push(`r.status = $${i++}`);        values.push(status); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';

  try {
    const [totals, byStatus, byType, byPriority, monthly, topRequesters] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS total FROM requests r ${where}`, values),
      pool.query(`SELECT r.status, COUNT(*)::int AS count FROM requests r ${where} GROUP BY r.status ORDER BY count DESC`, values),
      pool.query(`SELECT r.request_type, COUNT(*)::int AS count FROM requests r ${where} GROUP BY r.request_type`, values),
      pool.query(`SELECT r.priority, COUNT(*)::int AS count FROM requests r ${where} GROUP BY r.priority`, values),
      pool.query(`SELECT TO_CHAR(r.created_at, 'Mon YY') AS month,
                         TO_CHAR(r.created_at, 'YYYY-MM') AS month_key,
                         COUNT(*)::int AS count
        FROM requests r ${where}
        GROUP BY month, month_key
        ORDER BY month_key DESC LIMIT 6`, values),
      pool.query(`SELECT u.username AS requester, COUNT(r.request_id)::int AS count
        FROM requests r LEFT JOIN users u ON r.requested_by = u.user_id
        ${where}
        GROUP BY u.username ORDER BY count DESC LIMIT 10`, values)
    ]);

    res.json({
      totals:         totals.rows[0],
      by_status:      byStatus.rows,
      by_type:        byType.rows,
      by_priority:    byPriority.rows,
      monthly:        monthly.rows.reverse(),
      top_requesters: topRequesters.rows
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reports/loans', isAuthenticated, isReportViewer, async (req, res) => {
  const { from, to } = req.query;
  const conds = [];
  const values = [];
  let i = 1;
  if (from) { conds.push(`l.loan_date >= $${i++}`); values.push(from); }
  if (to)   { conds.push(`l.loan_date <= $${i++}`); values.push(to); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';

  try {
    const [totals, byStatus, topCustomers, monthly] = await Promise.all([
      pool.query(`SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE l.status='active')::int AS active,
        COUNT(*) FILTER (WHERE l.status='active' AND l.due_date < CURRENT_DATE)::int AS overdue,
        COUNT(*) FILTER (WHERE l.status='returned')::int AS returned,
        COUNT(*) FILTER (WHERE l.payment_status='paid')::int AS paid,
        COALESCE(SUM(l.total_charge), 0)::float AS revenue
        FROM loans l ${where}`, values),
      pool.query(`SELECT l.status, COUNT(*)::int AS count FROM loans l ${where} GROUP BY l.status`, values),
      pool.query(`SELECT l.customer_name, COUNT(*)::int AS loans,
        COALESCE(SUM(l.total_charge), 0)::float AS total_charge
        FROM loans l ${where}
        GROUP BY l.customer_name
        ORDER BY loans DESC LIMIT 10`, values),
      pool.query(`SELECT TO_CHAR(l.loan_date, 'Mon YY') AS month,
                         TO_CHAR(l.loan_date, 'YYYY-MM') AS month_key,
                         COUNT(*)::int AS count
        FROM loans l ${where}
        GROUP BY month, month_key
        ORDER BY month_key DESC LIMIT 6`, values)
    ]);

    res.json({
      totals:        totals.rows[0],
      by_status:     byStatus.rows,
      top_customers: topCustomers.rows,
      monthly:       monthly.rows.reverse()
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// REPORTS — ASSETS
// =============================================================
app.get('/api/reports/assets', isAuthenticated, isReportViewer, async (req, res) => {
  const { category, status } = req.query;
  const conds = [];
  const values = [];
  let i = 1;
  if (category) { conds.push(`category = $${i++}`); values.push(category); }
  if (status)   { conds.push(`status = $${i++}`);   values.push(status); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';

  try {
    const [totals, byCategory, byStatus, recent] = await Promise.all([
      pool.query(`SELECT
        COUNT(*) FILTER (WHERE status IN ('in_stock','taken_out'))::int AS total,
        COUNT(*) FILTER (WHERE status = 'in_stock')::int                  AS in_stock,
        COUNT(*) FILTER (WHERE status = 'taken_out')::int                 AS taken_out,
        COUNT(*) FILTER (WHERE status = 'decomposed')::int                AS decomposed,
        COUNT(DISTINCT category) FILTER (WHERE category IS NOT NULL AND status IN ('in_stock','taken_out'))::int AS categories
        FROM assets ${where}`, values),

      pool.query(`SELECT category,
        COUNT(*) FILTER (WHERE status IN ('in_stock','taken_out'))::int AS total,
        COUNT(*) FILTER (WHERE status='in_stock')::int                   AS in_stock,
        COUNT(*) FILTER (WHERE status='taken_out')::int                  AS taken_out,
        COUNT(*) FILTER (WHERE status='decomposed')::int                 AS decomposed
        FROM assets ${where}
        GROUP BY category
        ORDER BY total DESC, category ASC`, values),

      pool.query(`SELECT status, COUNT(*)::int AS count
        FROM assets ${where}
        GROUP BY status`, values),

      pool.query(`SELECT asset_id, part, serial, category, description, rack, status,
                         added_at, removed_at
        FROM assets ${where}
        ORDER BY asset_id DESC
        LIMIT 20`, values)
    ]);

    res.json({
      totals:       totals.rows[0],
      by_category:  byCategory.rows,
      by_status:    byStatus.rows,
      recent:       recent.rows
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =============================================================
// REPORTS — SO CODE USAGE
// =============================================================
// =============================================================
// REPORTS — SO CODE USAGE
// =============================================================
app.get('/api/reports/so-code-usage', isAuthenticated, isReportViewer, async (req, res) => {
  const { q, status, from, to } = req.query;
  const conds = ["r.request_type = 'external'", "r.so_code_id IS NOT NULL"];
  const values = [];
  let i = 1;

  if (q) {
    conds.push(`(sc.so_number ILIKE $${i} OR sc.partner_customer ILIKE $${i})`);
    values.push(`%${q}%`);
    i++;
  }
  if (status) {
    conds.push(`sc.status = $${i++}`);
    values.push(status);
  }
  if (from) {
    conds.push(`r.created_at >= $${i++}`);
    values.push(from);
  }
  if (to) {
    conds.push(`r.created_at <= $${i++}`);
    values.push(to);
  }
  const where = `WHERE ${conds.join(' AND ')}`;

  try {
    const [rows, totals] = await Promise.all([
      pool.query(`
        SELECT
          sc.id                AS so_code_id,
          sc.so_number,
          sc.partner_customer,
          sc.status,
          COUNT(DISTINCT r.request_id)::int   AS request_count,
          COUNT(DISTINCT r.requested_by)::int AS user_count,
          COALESCE(SUM(q.price), 0)::float    AS total_spent
        FROM so_codes sc
        JOIN requests r ON r.so_code_id = sc.id
        LEFT JOIN LATERAL (
          SELECT price FROM quotations
          WHERE request_id = r.request_id
          ORDER BY created_at DESC LIMIT 1
        ) q ON TRUE
        ${where}
        GROUP BY sc.id, sc.so_number, sc.partner_customer, sc.status
        HAVING COUNT(DISTINCT r.request_id) > 0
        ORDER BY request_count DESC, total_spent DESC
      `, values),

      pool.query(`
        SELECT
          COUNT(DISTINCT sc.id)::int            AS so_codes_used,
          COUNT(DISTINCT r.request_id)::int     AS total_requests,
          COUNT(DISTINCT r.requested_by)::int   AS total_users,
          COALESCE(SUM(q.price), 0)::float      AS total_spent
        FROM so_codes sc
        JOIN requests r ON r.so_code_id = sc.id
        LEFT JOIN LATERAL (
          SELECT price FROM quotations
          WHERE request_id = r.request_id
          ORDER BY created_at DESC LIMIT 1
        ) q ON TRUE
        ${where}
      `, values)
    ]);

    res.json({ totals: totals.rows[0], rows: rows.rows });
  } catch (err) {
    console.error('[so-code-usage]', err);
    res.status(500).json({ error: err.message });
  }
});

// =============================================================
// REPORTS — Requests under one SO Code
// =============================================================
app.get('/api/reports/so-code-usage/:soId/requests', isAuthenticated, isReportViewer, async (req, res) => {
  const soId = req.params.soId;
  const { from, to } = req.query;
  const conds = ["r.so_code_id = $1", "r.request_type = 'external'"];
  const values = [soId];
  let i = 2;
  if (from) { conds.push(`r.created_at >= $${i++}`); values.push(from); }
  if (to)   { conds.push(`r.created_at <= $${i++}`); values.push(to); }
  const where = `WHERE ${conds.join(' AND ')}`;

  try {
    const result = await pool.query(`
      SELECT
        r.request_id,
        r.part,
        r.description,
        r.qty,
        r.justification    AS notes,
        r.status,
        r.created_at,
        u.username         AS requester_name,
        u.full_name        AS requester_full,
        q.price            AS price
      FROM requests r
      LEFT JOIN users u ON r.requested_by = u.user_id
      LEFT JOIN LATERAL (
        SELECT price FROM quotations
        WHERE request_id = r.request_id
        ORDER BY created_at DESC LIMIT 1
      ) q ON TRUE
      ${where}
      ORDER BY r.created_at DESC
    `, values);
    res.json(result.rows);
  } catch (err) {
    console.error('[so-code-usage-requests]', err);
    res.status(500).json({ error: err.message });
  }
});

// =============================================================
// REPORTS — Users under one SO Code
// =============================================================
app.get('/api/reports/so-code-usage/:soId/users', isAuthenticated, isReportViewer, async (req, res) => {
  const soId = req.params.soId;
  const { from, to } = req.query;
  const conds = ["r.so_code_id = $1", "r.request_type = 'external'"];
  const values = [soId];
  let i = 2;
  if (from) { conds.push(`r.created_at >= $${i++}`); values.push(from); }
  if (to)   { conds.push(`r.created_at <= $${i++}`); values.push(to); }
  const where = `WHERE ${conds.join(' AND ')}`;

  try {
    const result = await pool.query(`
      SELECT
        COALESCE(u.username, 'unknown') AS username,
        COALESCE(u.full_name, '')       AS full_name,
        COUNT(DISTINCT r.request_id)::int AS request_count,
        COALESCE(SUM(q.price), 0)::float  AS total_spent
      FROM requests r
      LEFT JOIN users u ON r.requested_by = u.user_id
      LEFT JOIN LATERAL (
        SELECT price FROM quotations
        WHERE request_id = r.request_id
        ORDER BY created_at DESC LIMIT 1
      ) q ON TRUE
      ${where}
      GROUP BY u.username, u.full_name
      ORDER BY request_count DESC, total_spent DESC
    `, values);
    res.json(result.rows);
  } catch (err) {
    console.error('[so-code-usage-users]', err);
    res.status(500).json({ error: err.message });
  }
});

// =============================================================
// SEED ADMIN
// =============================================================
async function seedAdmin() {
  try {
    const username = process.env.SEED_ADMIN_USER;
    const password = process.env.SEED_ADMIN_PASS;

    if (!username || !password) {
      console.log('ℹ️  No SEED_ADMIN_USER / SEED_ADMIN_PASS in .env — skipping admin seed.');
      return;
    }

    if (password.length < 6) {
      console.warn('⚠️  SEED_ADMIN_PASS is shorter than 6 characters. Refusing to seed.');
      return;
    }

    const check = await pool.query('SELECT 1 FROM users WHERE username = $1', [username]);
    if (check.rows.length === 0) {
      const hashedPassword = await bcrypt.hash(password, 10);
      await pool.query(
        'INSERT INTO users (username, password_hash, role, full_name) VALUES ($1, $2, $3, $4)',
        [username, hashedPassword, 'admin', 'System Administrator']
      );
      console.log(`✅ Seeded admin user: ${username}`);
    }
  } catch (err) {
    console.error('Seed error:', err.message);
  }
}
seedAdmin();

app.get('/api/user/theme', async (req, res) => {
  if (!req.session.userId) return res.json({ theme: 'dark' });
  try {
    const result = await pool.query('SELECT pref_theme FROM users WHERE user_id = $1', [req.session.userId]);
    const theme = result.rows[0]?.pref_theme || 'dark';
    res.json({ theme });
  } catch (err) { res.json({ theme: 'dark' }); }
});

// =============================================================
// START
// =============================================================
const httpsOptions = {
  key:  fs.readFileSync(path.join(__dirname, 'certificates', 'key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'certificates', 'cert.pem'))
};

const displayUrl = process.env.PUBLIC_URL || `https://localhost:${port}`;

https.createServer(httpsOptions, app).listen(port, '0.0.0.0', () => {
  console.log(`✅ HTTPS running — display URL: ${displayUrl}`);
  console.log(`   (actual bind: 0.0.0.0:${port})`);
  console.log(`📧 SMTP: ${process.env.SMTP_HOST}:${process.env.SMTP_PORT} as ${SMTP_USER}`);
  console.log(`📥 IMAP: ${IMAP_HOST}:${IMAP_PORT} as ${IMAP_USER}`);

  // SO Codes — initial sync + periodic refresh
  if (EXA_API_URL && EXA_API_KEY) {
    setTimeout(async () => {
      try { await syncSOCodes(); }
      catch (e) { console.error('[initial so-sync]', e.message); }
    }, 3000);

    setInterval(async () => {
      try { await syncSOCodes(); }
      catch (e) { console.error('[periodic so-sync]', e.message); }
    }, SO_SYNC_INTERVAL_MS);
  }
});