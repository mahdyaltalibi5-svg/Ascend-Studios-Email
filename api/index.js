'use strict';

const crypto = require('crypto');
const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.SUPABASE_DB_URL;
const adminKey = process.env.ADMIN_KEY || '';
let pool;
let ready;

function getPool() {
  if (!connectionString) throw Object.assign(new Error('Missing database connection variable.'), { statusCode: 503 });
  if (!pool) {
    pool = new Pool({
      connectionString,
      ssl: { rejectUnauthorized: false },
      max: 3,
      idleTimeoutMillis: 20000,
      connectionTimeoutMillis: 10000
    });
  }
  return pool;
}

async function ensureDatabase() {
  if (!ready) {
    ready = getPool().query(`
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
      CREATE INDEX IF NOT EXISTS idx_subscribers_created ON subscribers(created_at, id);
      CREATE INDEX IF NOT EXISTS idx_subscribers_referrer ON subscribers(referred_by);
    `).catch((error) => {
      ready = undefined;
      throw error;
    });
  }
  return ready;
}

function json(res, status, data) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(data));
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function validEmail(value) {
  return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function makeCode() {
  return crypto.randomBytes(7).toString('base64url');
}

function safeKey(candidate) {
  if (!adminKey || !candidate) return false;
  const a = Buffer.from(String(candidate));
  const b = Buffer.from(adminKey);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function getBody(req) {
  if (req.body && typeof req.body === 'object') return Promise.resolve(req.body);
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 20000) reject(new Error('Payload too large'));
    });
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

async function publicRecord(row) {
  const result = await getPool().query(
    `SELECT COUNT(*)::int AS position FROM subscribers
     WHERE created_at < $1 OR (created_at = $1 AND id <= $2)`,
    [row.created_at, row.id]
  );
  return { position: result.rows[0].position, code: row.code, referral_count: row.referral_count || 0 };
}

async function subscribe(req, res) {
  let body;
  try { body = await getBody(req); }
  catch (error) { return json(res, 400, { error: error.message }); }

  const email = normalizeEmail(body.email);
  const ref = String(body.ref || '').trim();
  const honeypot = String(body.website || '').trim();

  if (honeypot) return json(res, 200, { position: 1, code: 'accepted', referral_count: 0 });
  if (!validEmail(email)) return json(res, 400, { error: 'Enter a valid email address.' });

  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const existing = await client.query('SELECT * FROM subscribers WHERE email = $1 FOR UPDATE', [email]);
    if (existing.rowCount) {
      await client.query('COMMIT');
      return json(res, 200, await publicRecord(existing.rows[0]));
    }

    let referrerId = null;
    if (ref) {
      const found = await client.query('SELECT id FROM subscribers WHERE code = $1 FOR UPDATE', [ref]);
      if (found.rowCount) referrerId = found.rows[0].id;
    }

    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    const ipHash = forwarded
      ? crypto.createHash('sha256').update(forwarded + (process.env.IP_SALT || 'ascend-studios')).digest('hex')
      : null;
    const userAgent = String(req.headers['user-agent'] || '').slice(0, 500);

    let inserted;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        inserted = await client.query(
          `INSERT INTO subscribers (email, code, referred_by, ip_hash, user_agent)
           VALUES ($1, $2, $3, $4, $5) RETURNING *`,
          [email, makeCode(), referrerId, ipHash, userAgent]
        );
        break;
      } catch (error) {
        if (error.code !== '23505' || attempt === 4) throw error;
      }
    }

    if (referrerId) {
      await client.query('UPDATE subscribers SET referral_count = referral_count + 1 WHERE id = $1', [referrerId]);
    }
    await client.query('COMMIT');
    return json(res, 201, await publicRecord(inserted.rows[0]));
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(error);
    return json(res, 500, { error: 'Could not join the list. Try again.' });
  } finally {
    client.release();
  }
}

async function status(req, res, url) {
  const code = String(url.searchParams.get('code') || '').trim();
  if (!code) return json(res, 400, { error: 'Missing code.' });
  const result = await getPool().query('SELECT * FROM subscribers WHERE code = $1', [code]);
  if (!result.rowCount) return json(res, 404, { error: 'Subscriber not found.' });
  return json(res, 200, await publicRecord(result.rows[0]));
}

async function stats(res) {
  const result = await getPool().query(`
    SELECT COUNT(*)::int AS total,
      COUNT(*) FILTER (WHERE referred_by IS NOT NULL)::int AS referred_signups,
      COALESCE(MAX(referral_count), 0)::int AS top_referrals,
      COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::int AS last_24_hours
    FROM subscribers
  `);
  return json(res, 200, result.rows[0]);
}

async function exportCsv(res) {
  const result = await getPool().query(`
    SELECT s.email, s.code, s.referral_count, s.created_at, r.email AS referred_by_email
    FROM subscribers s LEFT JOIN subscribers r ON r.id = s.referred_by
    ORDER BY s.created_at, s.id
  `);
  const esc = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;
  const lines = ['position,email,code,referral_count,referred_by_email,created_at'];
  result.rows.forEach((row, index) => lines.push([
    index + 1, row.email, row.code, row.referral_count, row.referred_by_email,
    new Date(row.created_at).toISOString()
  ].map(esc).join(',')));
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="ascend-waitlist.csv"');
  res.end(lines.join('\n'));
}

function adminPage(res, key) {
  const encoded = encodeURIComponent(key);
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ASCEND Admin</title><style>body{margin:0;background:#09090b;color:#eee;font-family:Arial,sans-serif;padding:48px;max-width:900px}h1{letter-spacing:.2em;font-weight:500}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:32px 0}.card{border:1px solid #29292d;padding:20px;background:#111114}.n{font-size:36px;margin-top:8px}a{display:inline-block;background:#eee;color:#09090b;padding:14px 18px;text-decoration:none;font-weight:700}</style></head><body><h1>ASCEND WAITLIST</h1><div class="grid" id="stats">Loading…</div><a href="/api/admin/export.csv?key=${encoded}">Download CSV</a><script>fetch('/api/admin/stats?key=${encoded}').then(r=>r.json()).then(s=>{stats.innerHTML=[['Total',s.total],['Last 24h',s.last_24_hours],['Referral signups',s.referred_signups],['Top referrals',s.top_referrals]].map(x=>'<div class="card">'+x[0]+'<div class="n">'+x[1]+'</div></div>').join('')}).catch(()=>stats.textContent='Could not load stats')</script></body></html>`);
}

module.exports = async function handler(req, res) {
  const url = new URL(req.url, 'https://local.invalid');
  const path = url.pathname;
  try {
    await ensureDatabase();
    if (path === '/api/health') return json(res, 200, { ok: true });
    if (path === '/api/subscribe' && req.method === 'POST') return subscribe(req, res);
    if (path === '/api/subscribe' && req.method === 'GET') return status(req, res, url);

    const key = req.headers['x-admin-key'] || url.searchParams.get('key');
    if (path.startsWith('/api/admin/') || path === '/admin') {
      if (!safeKey(key)) return json(res, 401, { error: 'Unauthorized.' });
      if (path === '/api/admin/stats') return stats(res);
      if (path === '/api/admin/export.csv') return exportCsv(res);
      if (path === '/admin') return adminPage(res, String(key));
    }
    return json(res, 404, { error: 'Not found.' });
  } catch (error) {
    console.error(error);
    return json(res, error.statusCode || 503, {
      error: connectionString ? 'Database is unavailable.' : 'Database is not configured.'
    });
  }
};
