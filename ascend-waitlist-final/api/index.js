'use strict';

require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.SUPABASE_DB_URL;
const ADMIN_KEY = process.env.ADMIN_KEY;


const pool = DATABASE_URL ? new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
}) : null;

app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(compression());
app.use(express.json({ limit: '20kb' }));

const subscribeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 25,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again shortly.' },
});

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function makeCode() {
  return crypto.randomBytes(6).toString('base64url');
}

function timingSafeKeyMatch(candidate) {
  if (!ADMIN_KEY || !candidate) return false;
  const a = Buffer.from(String(candidate));
  const b = Buffer.from(String(ADMIN_KEY));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requireAdmin(req, res, next) {
  const candidate = req.get('x-admin-key') || req.query.key;
  if (!timingSafeKeyMatch(candidate)) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  next();
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS subscribers (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      code TEXT NOT NULL UNIQUE,
      referred_by BIGINT REFERENCES subscribers(id) ON DELETE SET NULL,
      referral_count INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ip_hash TEXT,
      user_agent TEXT
    );
  `);
  await pool.query('CREATE INDEX IF NOT EXISTS idx_subscribers_created_at ON subscribers(created_at, id);');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_subscribers_referred_by ON subscribers(referred_by);');
}

let databaseReady;

async function ensureDatabase() {
  if (!pool) {
    const error = new Error('Missing database URL. Add DATABASE_URL, POSTGRES_URL, or SUPABASE_DB_URL in Vercel.');
    error.statusCode = 503;
    throw error;
  }
  if (!databaseReady) {
    databaseReady = initializeDatabase().catch((error) => {
      databaseReady = undefined;
      throw error;
    });
  }
  return databaseReady;
}

app.use(async (req, res, next) => {
  if (!req.path.startsWith('/api') && req.path !== '/admin') return next();
  try {
    await ensureDatabase();
    next();
  } catch (error) {
    console.error('Database initialization failed:', error);
    const status = error.statusCode || 503;
    if (req.path === '/admin') return res.status(status).send('Database is not configured.');
    return res.status(status).json({ error: 'Database is not configured or unavailable.' });
  }
});

async function publicSubscriber(row) {
  const positionResult = await pool.query(
    `SELECT COUNT(*)::int AS position
       FROM subscribers
      WHERE created_at < $1 OR (created_at = $1 AND id <= $2)`,
    [row.created_at, row.id]
  );
  return {
    position: positionResult.rows[0].position,
    code: row.code,
    referral_count: row.referral_count,
  };
}

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(503).json({ ok: false });
  }
});

app.post('/api/subscribe', subscribeLimiter, async (req, res) => {
  const email = normalizeEmail(req.body && req.body.email);
  const ref = String((req.body && req.body.ref) || '').trim();
  const honeypot = String((req.body && req.body.website) || '').trim();

  if (honeypot) return res.status(200).json({ position: 1, code: 'accepted', referral_count: 0 });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });

  const ip = req.ip || '';
  const ipHash = ip ? crypto.createHash('sha256').update(ip + (process.env.IP_SALT || 'ascend')).digest('hex') : null;
  const userAgent = String(req.get('user-agent') || '').slice(0, 500);
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const existing = await client.query('SELECT * FROM subscribers WHERE email = $1 FOR UPDATE', [email]);
    if (existing.rowCount) {
      await client.query('COMMIT');
      return res.json(await publicSubscriber(existing.rows[0]));
    }

    let referrerId = null;
    if (ref) {
      const referrer = await client.query('SELECT id FROM subscribers WHERE code = $1 FOR UPDATE', [ref]);
      if (referrer.rowCount) referrerId = referrer.rows[0].id;
    }

    let inserted;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        inserted = await client.query(
          `INSERT INTO subscribers (email, code, referred_by, ip_hash, user_agent)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING *`,
          [email, makeCode(), referrerId, ipHash, userAgent]
        );
        break;
      } catch (error) {
        if (error.code !== '23505' || attempt === 4) throw error;
      }
    }

    if (referrerId) {
      await client.query(
        'UPDATE subscribers SET referral_count = referral_count + 1 WHERE id = $1',
        [referrerId]
      );
    }

    await client.query('COMMIT');
    return res.status(201).json(await publicSubscriber(inserted.rows[0]));
  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    return res.status(500).json({ error: 'Could not join the list. Try again.' });
  } finally {
    client.release();
  }
});

app.get('/api/subscribe', async (req, res) => {
  const code = String(req.query.code || '').trim();
  if (!code) return res.status(400).json({ error: 'Missing code.' });

  try {
    const result = await pool.query('SELECT * FROM subscribers WHERE code = $1', [code]);
    if (!result.rowCount) return res.status(404).json({ error: 'Subscriber not found.' });
    return res.json(await publicSubscriber(result.rows[0]));
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Could not load waitlist status.' });
  }
});

app.get('/api/admin/stats', requireAdmin, async (_req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE referred_by IS NOT NULL)::int AS referred_signups,
        COALESCE(MAX(referral_count), 0)::int AS top_referrals,
        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::int AS last_24_hours
      FROM subscribers
    `);
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load stats.' });
  }
});

app.get('/api/admin/export.csv', requireAdmin, async (_req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.id, s.email, s.code, s.referral_count, s.created_at,
             r.email AS referred_by_email
      FROM subscribers s
      LEFT JOIN subscribers r ON r.id = s.referred_by
      ORDER BY s.created_at ASC, s.id ASC
    `);

    const escapeCsv = (value) => '"' + String(value ?? '').replace(/"/g, '""') + '"';
    const header = ['position', 'email', 'code', 'referral_count', 'referred_by_email', 'created_at'];
    const lines = [header.join(',')];
    result.rows.forEach((row, index) => {
      lines.push([
        index + 1,
        row.email,
        row.code,
        row.referral_count,
        row.referred_by_email,
        new Date(row.created_at).toISOString(),
      ].map(escapeCsv).join(','));
    });

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="ascend-waitlist.csv"');
    res.send(lines.join('\n'));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not export subscribers.' });
  }
});

app.get('/admin', (req, res) => {
  const key = String(req.query.key || '');
  if (!timingSafeKeyMatch(key)) return res.status(401).send('Unauthorized');
  const safeKey = encodeURIComponent(key);
  res.type('html').send(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ASCEND Waitlist Admin</title><style>
body{font-family:system-ui;background:#0b0b0d;color:#e8e4da;max-width:760px;margin:60px auto;padding:24px}h1{letter-spacing:.12em}section{border:1px solid #333;padding:24px;margin:24px 0;background:#17171b}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px}.stat{padding:16px;border:1px solid #333}.num{font-size:32px;font-weight:700}a{display:inline-block;background:#e8e4da;color:#0b0b0d;padding:12px 18px;text-decoration:none;font-weight:700}small{color:#999}</style></head>
<body><h1>ASCEND WAITLIST</h1><section><div class="stats" id="stats">Loading…</div></section><section><a href="/api/admin/export.csv?key=${safeKey}">Download CSV</a><p><small>Keep this admin URL private.</small></p></section>
<script>fetch('/api/admin/stats?key=${safeKey}').then(r=>r.json()).then(s=>{document.getElementById('stats').innerHTML=[['Total',s.total],['Last 24h',s.last_24_hours],['Referral signups',s.referred_signups],['Top referrals',s.top_referrals]].map(x=>'<div class="stat"><div>'+x[0]+'</div><div class="num">'+x[1]+'</div></div>').join('')}).catch(()=>document.getElementById('stats').textContent='Could not load stats.')</script></body></html>`);
});

module.exports = app;
