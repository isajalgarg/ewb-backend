/**
 * EWB MIS Backend — indianmetaltrading.com
 * ─────────────────────────────────────────
 * PostgreSQL edition  (pg + node-fetch)
 * Full 4-step Sandbox auth · deduplication
 * Invoice-centric model · SSE fetch progress
 */

const express  = require('express');
const cors     = require('cors');
const { Pool } = require('pg');
const fetch    = (...args) => import('node-fetch').then(m => m.default(...args));
const path     = require('path');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// ── PostgreSQL connection pool ──
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis:    30000,
  connectionTimeoutMillis: 5000,
});
pool.on('error', err => console.error('PG pool error:', err.message));

// ─────────────────────────────────────────────
//  Schema initialisation
// ─────────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`

      -- ── Main EWB table ──────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS ewbs (
        id               TEXT PRIMARY KEY,          -- 'EWB-{ewbNo}'
        ewb_no           TEXT UNIQUE NOT NULL,       -- globally unique (GST portal)
        invoice_no       TEXT NOT NULL,              -- docNo — primary business key
        invoice_date     TEXT,
        ewb_date         TEXT,
        ewb_status       TEXT    DEFAULT 'ACT',      -- ACT | CNL
        valid_upto       TEXT,
        rejected         BOOLEAN DEFAULT FALSE,
        rejected_date    TEXT,
        gen_gstin        TEXT,

        -- From party
        from_party       TEXT,
        from_gstin       TEXT,
        from_place       TEXT,
        from_pincode     TEXT,
        from_state       TEXT,

        -- To party
        to_party         TEXT,
        to_gstin         TEXT,
        to_place         TEXT,
        to_pincode       TEXT,
        to_state         TEXT,

        -- Goods
        material         TEXT,
        hsn              TEXT,
        quantity         NUMERIC(14,3) DEFAULT 0,
        qty_unit         TEXT,
        taxable_amt      NUMERIC(14,2) DEFAULT 0,
        igst_amt         NUMERIC(14,2) DEFAULT 0,
        cgst_amt         NUMERIC(14,2) DEFAULT 0,
        sgst_amt         NUMERIC(14,2) DEFAULT 0,
        cess_amt         NUMERIC(14,2) DEFAULT 0,
        total_inv_value  NUMERIC(14,2) DEFAULT 0,

        -- Transport
        vehicle_no       TEXT,
        transporter_id   TEXT,
        transporter_name TEXT,
        distance         TEXT,
        trans_mode       TEXT,

        -- Fetch meta
        detail_fetched   BOOLEAN DEFAULT FALSE,
        source           TEXT    DEFAULT 'API',
        fetched_at       TIMESTAMPTZ,

        -- ── Ops layer (team-entered, never overwritten by API sync) ──
        rate             NUMERIC(14,2),
        amount           NUMERIC(14,2),
        igst_entered     NUMERIC(14,2),
        invoice_value    NUMERIC(14,2),
        vstatus          TEXT DEFAULT 'PENDING',   -- PENDING | IN TRANSIT | REACHED
        reached_date     DATE,
        ulstatus         TEXT DEFAULT 'PENDING',   -- PENDING | IN PROGRESS | DONE
        ul_date          DATE,
        remarks          TEXT,
        ops_done         BOOLEAN DEFAULT FALSE,

        created_at       TIMESTAMPTZ DEFAULT NOW(),
        updated_at       TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_ewbs_invoice_no ON ewbs(invoice_no);
      CREATE INDEX IF NOT EXISTS idx_ewbs_ewb_date   ON ewbs(ewb_date);
      CREATE INDEX IF NOT EXISTS idx_ewbs_vstatus    ON ewbs(vstatus);
      CREATE INDEX IF NOT EXISTS idx_ewbs_ewb_status ON ewbs(ewb_status);

      ALTER TABLE ewbs ADD COLUMN IF NOT EXISTS txn_id       TEXT;
      ALTER TABLE ewbs ADD COLUMN IF NOT EXISTS fetch_source TEXT DEFAULT 'auto';

      -- ── Fetch history ────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS fetch_log (
        id             SERIAL PRIMARY KEY,
        date_from      DATE,
        date_to        DATE,
        ewbs_found     INT DEFAULT 0,
        ewbs_added     INT DEFAULT 0,
        ewbs_updated   INT DEFAULT 0,
        ewbs_failed    INT DEFAULT 0,
        detail_fetched INT DEFAULT 0,
        duration_ms    INT DEFAULT 0,
        fetched_at     TIMESTAMPTZ DEFAULT NOW()
      );

      -- ── Key-value store (credentials + token cache) ──────────────────
      CREATE TABLE IF NOT EXISTS kv_store (
        key        TEXT PRIMARY KEY,
        value      TEXT,
        expires_at BIGINT,               -- unix epoch ms; NULL = never expires
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

    `);
    console.log('✓ PostgreSQL schema ready');
  } finally {
    client.release();
  }
}

// ─────────────────────────────────────────────
//  KV helpers  (credentials + token cache)
// ─────────────────────────────────────────────
async function kvGet(key) {
  const { rows } = await pool.query(
    'SELECT value, expires_at FROM kv_store WHERE key = $1', [key]
  );
  if (!rows.length) return null;
  const { value, expires_at } = rows[0];
  if (expires_at && Date.now() > Number(expires_at)) return null; // expired
  return value;
}

async function kvSet(key, value, expiresInMs = null) {
  const exp = expiresInMs ? Date.now() + expiresInMs : null;
  await pool.query(`
    INSERT INTO kv_store (key, value, expires_at, updated_at)
    VALUES ($1, $2, $3, NOW())
    ON CONFLICT (key) DO UPDATE SET
      value      = EXCLUDED.value,
      expires_at = EXCLUDED.expires_at,
      updated_at = NOW()
  `, [key, value === null ? null : String(value), exp]);
}

async function kvClear(...keys) {
  for (const k of keys) await kvSet(k, null, 1); // expire immediately
}

// ─────────────────────────────────────────────
//  Sandbox API — 4-step auth flow
// ─────────────────────────────────────────────
const SANDBOX = 'https://api.sandbox.co.in';

// Step 1 ── Sandbox JWT
async function getSandboxJWT(apiKey, apiSecret) {
  const cached = await kvGet('sandbox_jwt');
  if (cached) return cached;

  const res  = await fetch(`${SANDBOX}/authenticate`, {
    method: 'POST',
    headers: {
      'x-api-key':     apiKey,
      'x-api-secret':  apiSecret,
      'x-api-version': '1.0.0',
      'Content-Type':  'application/json',
    }
  });
  const data = await res.json();
  if (data.code !== 200 || !data.data?.access_token)
    throw new Error(`Sandbox JWT failed: ${JSON.stringify(data)}`);

  await kvSet('sandbox_jwt', data.data.access_token, 50 * 60 * 1000); // cache 50 min
  return data.data.access_token;
}

// Step 2 ── EWB portal token
async function getEWBToken(sandboxJWT, apiKey, ewbUser, ewbPass, gstin) {
  const cached = await kvGet('ewb_token');
  const expiry = await kvGet('ewb_token_expiry');
  if (cached && expiry && Date.now() < Number(expiry)) return cached;

  const res  = await fetch(`${SANDBOX}/gst/compliance/e-way-bill/tax-payer/authenticate`, {
    method: 'POST',
    headers: {
      'authorization':  sandboxJWT,
      'x-api-key':      apiKey,
      'x-api-version':  '1.0.0',
      'x-source':       'primary',
      'Content-Type':   'application/json',
    },
    body: JSON.stringify({ username: ewbUser, password: ewbPass, gstin })
  });
  const data = await res.json();
  if (data.code !== 200 || !data.data?.access_token)
    throw new Error(`EWB auth failed: ${JSON.stringify(data)}`);

  const token = data.data.access_token;
  const expMs = (data.data.expiry || 0) * 1000 || Date.now() + 6 * 3600 * 1000;
  await kvSet('ewb_token',        token,          null);
  await kvSet('ewb_token_expiry', String(expMs),  null);
  return token;
}

// Step 3 ── List EWBs by date
async function fetchEWBsByDate(ewbToken, apiKey, ddmmyyyy) {
  const res = await fetch(
    `${SANDBOX}/gst/compliance/e-way-bill/consignor/bills?generated_date=${encodeURIComponent(ddmmyyyy)}`,
    { headers: { authorization: ewbToken, 'x-api-key': apiKey, 'x-api-version': '1.0.0' } }
  );
  const data = await res.json();
  if (data.code !== 200) throw new Error(`List failed ${ddmmyyyy}: ${JSON.stringify(data)}`);
  return data.data?.data || [];
}

// Step 4 ── Full EWB detail

async function fetchEWBDetail(ewbToken, apiKey, ewbNo) {
  const url = `${SANDBOX}/gst/compliance/e-way-bill/tax-payer/bill/${ewbNo}`;
  console.log(`[Detail] Fetching EWB ${ewbNo} → ${url}`);

  const res  = await fetch(url,
    { headers: { authorization: ewbToken, 'x-api-key': apiKey, 'x-api-version': '1.0.0' } }
  );
  const data = await res.json();
  console.log(`[Detail] EWB ${ewbNo} raw:`, JSON.stringify(data));

  if (data.code !== 200) throw new Error(`Detail failed EWB ${ewbNo}: ${JSON.stringify(data)}`);

  const result = data.data?.data || data.data;
  if (!result) console.warn(`[Detail] EWB ${ewbNo} — code 200 but data is null`);
  return result;
}

// ── Map raw API detail to DB row ──
function mapDetail(d, ewbNo) {
  if (!d) { console.warn(`[mapDetail] null data for EWB ${ewbNo}`); return null; }
  const item = (d.itemList || d.ItemList || [])[0] || {};
  const n    = (v, def = 0) => parseFloat(v || def) || def;
  return {
    ewb_no:           String(ewbNo),
    invoice_no:       d.docNo               || null,
    invoice_date:     d.docDate             || null,
    ewb_date:         d.ewbDate             || null,
    ewb_status:       d.status              || 'ACT',
    valid_upto:       d.validUpto           || null,
    gen_gstin:        d.genGstin            || null,
    from_party:       d.fromTrdName         || null,
    from_gstin:       d.fromGstin           || null,
    from_place:       d.fromPlace           || null,
    from_pincode:     d.fromPincode         ? String(d.fromPincode)   : null,
    from_state:       d.actFromStateCode    ? String(d.actFromStateCode) : (d.fromStateCode ? String(d.fromStateCode) : null),
    to_party:         d.toTrdName           || null,
    to_gstin:         d.toGstin             || null,
    to_place:         d.toPlace             || null,
    to_pincode:       d.toPincode           ? String(d.toPincode)     : null,
    to_state:         d.actToStateCode      ? String(d.actToStateCode) : (d.toStateCode ? String(d.toStateCode) : null),
    material:         item.productDesc      || item.productName       || null,  // ← was productName first, raw has productDesc
    hsn:              item.hsnCode          ? String(item.hsnCode)    : null,
    quantity:         n(item.quantity),
    qty_unit:         item.qtyUnit          || 'MT',
    taxable_amt:      n(item.taxableAmount  || d.totalValue),          // ← raw has taxableAmount on item
    igst_amt:         n(d.igstValue),
    cgst_amt:         n(d.cgstValue),
    sgst_amt:         n(d.sgstValue),
    cess_amt:         n(d.cessValue),
    total_inv_value:  n(d.totInvValue),
    vehicle_no:       (d.VehiclListDetails  || [])[0]?.vehicleNo      || null,  // ← raw has VehiclListDetails array
    transporter_id:   d.transporterId       || null,
    transporter_name: d.transporterName     || null,
    distance:         d.actualDist          ? String(d.actualDist)    : null,   // ← raw has actualDist not distance
    trans_mode:       (d.VehiclListDetails  || [])[0]?.transMode      || null,
  };
}

// ── Date utilities ──
const isoToEWB = iso => { const [y,m,d] = iso.split('-'); return `${d}/${m}/${y}`; };
function dateRange(from, to) {
  const out = [], cur = new Date(from), end = new Date(to);
  while (cur <= end) { out.push(cur.toISOString().split('T')[0]); cur.setDate(cur.getDate()+1); }
  return out;
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─────────────────────────────────────────────
//  Middleware
// ─────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString().slice(11,19)}] ${req.method} ${req.path}`);
  next();
});

// ─────────────────────────────────────────────
//  ROUTES
// ─────────────────────────────────────────────

// ── Health ──────────────────────────────────
app.get('/health', async (req, res) => {
  try {
    const { rows: [r] } = await pool.query('SELECT COUNT(*) AS c FROM ewbs');
    res.json({ status: 'ok', ewbs: Number(r.c), time: new Date().toISOString() });
  } catch (e) { res.status(500).json({ status: 'db_error', error: e.message }); }
});

// ── Credentials ─────────────────────────────
app.post('/api/config', async (req, res) => {
  const { apiKey, apiSecret, ewbUsername, ewbPassword, gstin } = req.body;
  if (!apiKey || !apiSecret || !ewbUsername || !ewbPassword || !gstin)
    return res.status(400).json({ error: 'All fields required' });

  await kvSet('cfg_api_key',      apiKey);
  await kvSet('cfg_api_secret',   apiSecret);
  await kvSet('cfg_ewb_username', ewbUsername);
  await kvSet('cfg_ewb_password', ewbPassword);
  await kvSet('cfg_gstin',        gstin.toUpperCase());
  await kvClear('sandbox_jwt', 'ewb_token', 'ewb_token_expiry');
  res.json({ ok: true, message: 'Credentials saved' });
});

app.get('/api/config', async (req, res) => {
  const apiKey = await kvGet('cfg_api_key');
  const secret = await kvGet('cfg_api_secret');
  const user   = await kvGet('cfg_ewb_username');
  const gstin  = await kvGet('cfg_gstin');
  res.json({
    apiKey:      apiKey  ? '••••' + apiKey.slice(-4)  : null,
    apiSecret:   secret  ? '••••' + secret.slice(-4)  : null,
    ewbUsername: user    || null,
    gstin:       gstin   || null,
    configured:  !!(apiKey && user),
  });
});

// ── Authentication ───────────────────────────
app.post('/api/auth', async (req, res) => {
  try {
    const [apiKey, apiSecret, user, pass, gstin] = await Promise.all([
      kvGet('cfg_api_key'), kvGet('cfg_api_secret'),
      kvGet('cfg_ewb_username'), kvGet('cfg_ewb_password'),
      kvGet('cfg_gstin'),
    ]);
    if (!apiKey || !user)
      return res.status(400).json({ error: 'Credentials not configured — go to Config tab first' });

    await kvClear('sandbox_jwt', 'ewb_token', 'ewb_token_expiry');

    const sandboxJWT = await getSandboxJWT(apiKey, apiSecret);
    const ewbToken   = await getEWBToken(sandboxJWT, apiKey, user, pass, gstin);
    const expiry     = await kvGet('ewb_token_expiry');

    res.json({
      ok:            true,
      message:       'Authenticated successfully',
      expiry:        expiry ? new Date(Number(expiry)).toISOString() : null,
      token_preview: ewbToken.substring(0, 20) + '...',
    });
  } catch (e) {
    console.error('Auth error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/auth/status', async (req, res) => {
  const [tok, exp] = await Promise.all([kvGet('ewb_token'), kvGet('ewb_token_expiry')]);
  const valid = tok && exp && Date.now() < Number(exp);
  res.json({
    authenticated: !!valid,
    expiry:        exp  ? new Date(Number(exp)).toISOString() : null,
    remaining_ms:  exp  ? Math.max(0, Number(exp) - Date.now()) : 0,
  });
});

// ── Fetch EWBs  (SSE — Steps 3 + 4) ─────────
app.post('/api/fetch', async (req, res) => {
  const { dateFrom, dateTo, fetchDetails = true } = req.body;
  if (!dateFrom || !dateTo)
    return res.status(400).json({ error: 'dateFrom and dateTo required (YYYY-MM-DD)' });

  const [apiKey, apiSecret, user, pass, gstin] = await Promise.all([
    kvGet('cfg_api_key'), kvGet('cfg_api_secret'),
    kvGet('cfg_ewb_username'), kvGet('cfg_ewb_password'),
    kvGet('cfg_gstin'),
  ]);
  if (!apiKey) return res.status(400).json({ error: 'Not configured' });

  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.flushHeaders();

  const send  = d  => res.write(`data: ${JSON.stringify(d)}\n\n`);
  const t0    = Date.now();
  const stats = { found: 0, added: 0, updated: 0, failed: 0, detailFetched: 0 };

  try {
    // Step 1 — always fresh sandbox JWT + EWB token to avoid 403
    await kvClear('sandbox_jwt', 'ewb_token', 'ewb_token_expiry');
    send({ type: 'log', msg: 'Step 1 — Getting Sandbox JWT...' });
    const sandboxJWT = await getSandboxJWT(apiKey, apiSecret);
    send({ type: 'log', msg: '✓ Sandbox JWT obtained' });

    // Step 2
    send({ type: 'log', msg: 'Step 2 — Getting EWB portal token...' });
    const ewbToken = await getEWBToken(sandboxJWT, apiKey, user, pass, gstin);
    send({ type: 'log', msg: '✓ EWB token obtained' });

    // Step 3 — list by date
    const dates = dateRange(dateFrom, dateTo);
    send({ type: 'log', msg: `Step 3 — Fetching EWB list for ${dates.length} day(s)...` });

    const allEwbs = [];
    for (const iso of dates) {
      try {
        const list = await fetchEWBsByDate(ewbToken, apiKey, isoToEWB(iso));
        send({ type: 'log', msg: `  → ${iso}: ${list.length} EWB(s) found` });
        allEwbs.push(...list);
        stats.found += list.length;
        await sleep(300); // rate-limit courtesy
      } catch (e) {
        send({ type: 'log', msg: `  ✗ ${iso}: ${e.message}`, level: 'error' });
      }
    }

    // Deduplicate by ewb_no
    const unique = new Map();
    allEwbs.forEach(e => unique.set(String(e.ewbNo), e));
    send({ type: 'log',      msg: `Unique EWBs after dedup: ${unique.size}` });
    send({ type: 'progress', total: unique.size, done: 0 });

    // Step 4 — upsert + detail
    let i = 0;
    for (const [ewbNo, ewb] of unique) {
      try {
        const internalId = `EWB-${ewbNo}`;

        // Check existence for accurate added/updated count
        const { rows: ex } = await pool.query(
          'SELECT id, detail_fetched FROM ewbs WHERE ewb_no = $1', [ewbNo]
        );
        const exists = ex[0] || null;

        // Upsert — ops columns are intentionally excluded from the UPDATE SET
        const txnId = Math.floor(100000000000 + Math.random() * 900000000000).toString();
        await pool.query(`
          INSERT INTO ewbs (id, ewb_no, invoice_no, invoice_date, ewb_date,
            ewb_status, valid_upto, rejected, rejected_date, gen_gstin, fetched_at,
            txn_id, fetch_source)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
          ON CONFLICT (ewb_no) DO UPDATE SET
            ewb_status    = EXCLUDED.ewb_status,
            valid_upto    = EXCLUDED.valid_upto,
            rejected      = EXCLUDED.rejected,
            rejected_date = EXCLUDED.rejected_date,
            fetched_at    = EXCLUDED.fetched_at,
            updated_at    = NOW()
        `, [
          internalId,
          ewbNo,
          ewb.docNo        || '',
          ewb.docDate      || null,
          ewb.ewbDate      || null,
          ewb.status       || 'ACT',
          ewb.validUpto    || null,
          ewb.rejectStatus === 'Y',
          ewb.rejectedDate || null,
          ewb.genGstin     || null,
          new Date(),
          txnId,
          'auto',
        ]);

        if (exists) stats.updated++; else stats.added++;

        // Fetch detail only for new records (or ones missing detail)
        if (fetchDetails && (!exists || !exists.detail_fetched)) {
          try {
            await sleep(200);
            const d = mapDetail(await fetchEWBDetail(ewbToken, apiKey, ewbNo), ewbNo);
            await pool.query(`
              UPDATE ewbs SET
                invoice_date     = $1,  from_party       = $2,  from_gstin       = $3,
                from_place       = $4,  from_pincode     = $5,  from_state       = $6,
                to_party         = $7,  to_gstin         = $8,  to_place         = $9,
                to_pincode       = $10, to_state         = $11, material         = $12,
                hsn              = $13, quantity         = $14, qty_unit         = $15,
                taxable_amt      = $16, igst_amt         = $17, cgst_amt         = $18,
                sgst_amt         = $19, cess_amt         = $20, total_inv_value  = $21,
                vehicle_no       = $22, transporter_id   = $23, transporter_name = $24,
                distance         = $25, trans_mode       = $26,
                detail_fetched   = TRUE, updated_at      = NOW()
              WHERE ewb_no = $27
            `, [
              d.invoice_date, d.from_party,    d.from_gstin,
              d.from_place,   d.from_pincode,  d.from_state,
              d.to_party,     d.to_gstin,      d.to_place,
              d.to_pincode,   d.to_state,      d.material,
              d.hsn,          d.quantity,      d.qty_unit,
              d.taxable_amt,  d.igst_amt,      d.cgst_amt,
              d.sgst_amt,     d.cess_amt,      d.total_inv_value,
              d.vehicle_no,   d.transporter_id,d.transporter_name,
              d.distance,     d.trans_mode,
              ewbNo,
            ]);
            stats.detailFetched++;
          } catch (de) {
            send({ type: 'log', msg: `  ⚠ Detail EWB ${ewbNo}: ${de.message}`, level: 'warn' });
          }
        }
      } catch (e) {
        stats.failed++;
        send({ type: 'log', msg: `  ✗ EWB ${ewbNo}: ${e.message}`, level: 'error' });
      }

      i++;
      if (i % 5 === 0) send({ type: 'progress', total: unique.size, done: i });
    }

    // Persist fetch log
    await pool.query(
      `INSERT INTO fetch_log
         (date_from, date_to, ewbs_found, ewbs_added, ewbs_updated, ewbs_failed, detail_fetched, duration_ms)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [dateFrom, dateTo, stats.found, stats.added, stats.updated, stats.failed, stats.detailFetched, Date.now() - t0]
    );

    send({ type: 'progress', total: unique.size, done: unique.size });
    send({ type: 'done', stats, duration_ms: Date.now() - t0 });

  } catch (e) {
    console.error('Fetch error:', e);
    send({ type: 'error', msg: e.message });
  } finally {
    res.end();
  }
});

// ── Fetch single EWB by number ────────────────
app.post('/api/fetch-single', async (req, res) => {
  const { ewbNo } = req.body;
  if (!ewbNo) return res.status(400).json({ ok: false, error: 'ewbNo required' });
  try {
    const [apiKey, apiSecret, user, pass, gstin] = await Promise.all([
      kvGet('cfg_api_key'), kvGet('cfg_api_secret'),
      kvGet('cfg_ewb_username'), kvGet('cfg_ewb_password'),
      kvGet('cfg_gstin'),
    ]);
    if (!apiKey) return res.status(401).json({ ok: false, error: 'API key not configured — save credentials first' });

    await kvClear('sandbox_jwt', 'ewb_token', 'ewb_token_expiry');
    const sandboxJWT = await getSandboxJWT(apiKey, apiSecret);
    const ewbToken   = await getEWBToken(sandboxJWT, apiKey, user, pass, gstin);

    const d = mapDetail(await fetchEWBDetail(ewbToken, apiKey, String(ewbNo)), String(ewbNo));
    const internalId = 'EWB-' + ewbNo;
    const txnId = Math.floor(100000000000 + Math.random() * 900000000000).toString();

    const { rows: ex } = await pool.query('SELECT id FROM ewbs WHERE ewb_no = $1', [ewbNo]);
    const isNew = !ex.length;

    await pool.query(`
      INSERT INTO ewbs (id, ewb_no, invoice_no, invoice_date, ewb_date, ewb_status, valid_upto, gen_gstin,
        from_party, from_gstin, from_place, from_pincode, from_state,
        to_party,   to_gstin,   to_place,   to_pincode,   to_state,
        material, hsn, quantity, qty_unit, taxable_amt, igst_amt, cgst_amt, sgst_amt, cess_amt, total_inv_value,
        vehicle_no, transporter_id, transporter_name, distance, trans_mode,
        detail_fetched, fetched_at, txn_id, fetch_source)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
              $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,
              TRUE, NOW(), $34, 'manual')
      ON CONFLICT (ewb_no) DO UPDATE SET
        invoice_no=EXCLUDED.invoice_no, invoice_date=EXCLUDED.invoice_date,
        ewb_date=EXCLUDED.ewb_date, ewb_status=EXCLUDED.ewb_status,
        valid_upto=EXCLUDED.valid_upto, gen_gstin=EXCLUDED.gen_gstin,
        from_party=EXCLUDED.from_party, from_gstin=EXCLUDED.from_gstin,
        from_place=EXCLUDED.from_place, from_state=EXCLUDED.from_state,
        to_party=EXCLUDED.to_party, to_gstin=EXCLUDED.to_gstin,
        to_place=EXCLUDED.to_place, to_state=EXCLUDED.to_state,
        material=EXCLUDED.material, hsn=EXCLUDED.hsn,
        quantity=EXCLUDED.quantity, qty_unit=EXCLUDED.qty_unit,
        taxable_amt=EXCLUDED.taxable_amt, igst_amt=EXCLUDED.igst_amt,
        cgst_amt=EXCLUDED.cgst_amt, sgst_amt=EXCLUDED.sgst_amt,
        total_inv_value=EXCLUDED.total_inv_value, vehicle_no=EXCLUDED.vehicle_no,
        transporter_id=EXCLUDED.transporter_id, transporter_name=EXCLUDED.transporter_name,
        distance=EXCLUDED.distance, trans_mode=EXCLUDED.trans_mode,
        fetch_source='manual', detail_fetched=TRUE, updated_at=NOW()
    `, [
      internalId, ewbNo, d.invoice_no||'', d.invoice_date, d.ewb_date, d.ewb_status, d.valid_upto, d.gen_gstin,
      d.from_party, d.from_gstin, d.from_place, d.from_pincode, d.from_state,
      d.to_party,   d.to_gstin,   d.to_place,   d.to_pincode,   d.to_state,
      d.material, d.hsn, d.quantity, d.qty_unit, d.taxable_amt, d.igst_amt, d.cgst_amt, d.sgst_amt, d.cess_amt, d.total_inv_value,
      d.vehicle_no, d.transporter_id, d.transporter_name, d.distance, d.trans_mode,
      txnId,
    ]);

    res.json({ ok: true, added: isNew, ewb_no: ewbNo, txn_id: txnId });
  } catch (e) {
    console.error('fetch-single error:', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ── All EWBs ─────────────────────────────────
app.get('/api/ewbs', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM ewbs ORDER BY ewb_date DESC NULLS LAST'
  );
  res.json({ ok: true, count: rows.length, data: rows });
});

// ── Invoice-grouped view ──────────────────────
app.get('/api/invoices', async (req, res) => {
  const { rows } = await pool.query(`
    SELECT
      invoice_no,
      COUNT(*)                                                  AS ewb_count,
      STRING_AGG(ewb_no, ',')                                   AS ewb_nos,
      MAX(invoice_date)                                         AS invoice_date,
      MIN(ewb_date)                                             AS first_ewb_date,
      MAX(ewb_date)                                             AS last_ewb_date,
      MAX(from_party)                                           AS from_party,
      MAX(to_party)                                             AS to_party,
      MAX(to_place)                                             AS to_place,
      MAX(material)                                             AS material,
      SUM(quantity)                                             AS total_qty,
      MAX(qty_unit)                                             AS qty_unit,
      MAX(taxable_amt)                                          AS taxable_amt,
      MAX(igst_amt)                                             AS igst_amt,
      MAX(total_inv_value)                                      AS total_inv_value,
      MAX(vehicle_no)                                           AS vehicle_no,
      MAX(ewb_status)                                           AS latest_ewb_status,
      MAX(rate)                                                 AS rate,
      MAX(invoice_value)                                        AS invoice_value,
      MAX(vstatus)                                              AS vstatus,
      MAX(ulstatus)                                             AS ulstatus,
      MAX(reached_date)                                         AS reached_date,
      MAX(remarks)                                              AS remarks,
      BOOL_OR(ops_done)                                         AS ops_done
    FROM ewbs
    GROUP BY invoice_no
    ORDER BY MAX(ewb_date) DESC NULLS LAST
  `);
  res.json({ ok: true, count: rows.length, data: rows });
});

// ── All EWBs under one invoice ────────────────
app.get('/api/invoices/:invoiceNo', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM ewbs WHERE invoice_no = $1 ORDER BY ewb_date DESC',
    [req.params.invoiceNo]
  );
  if (!rows.length) return res.status(404).json({ error: 'Invoice not found' });
  res.json({ ok: true, invoice_no: req.params.invoiceNo, ewb_count: rows.length, ewbs: rows });
});

// ── Update ops data ───────────────────────────
app.put('/api/ewbs/:id/ops', async (req, res) => {
  const { rate, amount, igst_entered, invoice_value,
          vstatus, reached_date, ulstatus, ul_date, remarks } = req.body;
  const ops_done = !!(rate && vstatus && vstatus !== 'PENDING');
  await pool.query(`
    UPDATE ewbs SET
      rate          = $1,  amount        = $2,  igst_entered  = $3,
      invoice_value = $4,  vstatus       = $5,  reached_date  = $6,
      ulstatus      = $7,  ul_date       = $8,  remarks       = $9,
      ops_done      = $10, updated_at    = NOW()
    WHERE id = $11
  `, [rate||null, amount||null, igst_entered||null, invoice_value||null,
      vstatus||'PENDING', reached_date||null, ulstatus||'PENDING',
      ul_date||null, remarks||null, ops_done, req.params.id]);
  res.json({ ok: true, ops_done });
});

// ── Quick inline status update ────────────────
app.patch('/api/ewbs/:id/status', async (req, res) => {
  const { vstatus, ulstatus, reached_date, ul_date } = req.body;
  await pool.query(`
    UPDATE ewbs SET
      vstatus      = COALESCE($1, vstatus),
      ulstatus     = COALESCE($2, ulstatus),
      reached_date = COALESCE($3, reached_date),
      ul_date      = COALESCE($4, ul_date),
      updated_at   = NOW()
    WHERE id = $5
  `, [vstatus||null, ulstatus||null, reached_date||null, ul_date||null, req.params.id]);
  res.json({ ok: true });
});

// ── Dashboard KPIs ────────────────────────────
app.get('/api/stats', async (req, res) => {
  const { rows: [s] } = await pool.query(`
    SELECT
      COUNT(*)                                                        AS total_ewbs,
      COUNT(DISTINCT invoice_no)                                      AS total_invoices,
      SUM(CASE WHEN ewb_status = 'ACT'      THEN 1 ELSE 0 END)       AS active_ewbs,
      SUM(CASE WHEN ewb_status = 'CNL'      THEN 1 ELSE 0 END)       AS cancelled_ewbs,
      SUM(CASE WHEN vstatus    = 'REACHED'  THEN 1 ELSE 0 END)       AS vehicles_reached,
      SUM(CASE WHEN vstatus    = 'IN TRANSIT' THEN 1 ELSE 0 END)     AS in_transit,
      SUM(CASE WHEN ulstatus   = 'DONE'     THEN 1 ELSE 0 END)       AS unloading_done,
      SUM(CASE WHEN ops_done   = TRUE       THEN 1 ELSE 0 END)       AS ops_complete,
      COALESCE(SUM(taxable_amt),0)                                    AS total_taxable,
      COALESCE(SUM(igst_amt),0)                                       AS total_igst,
      COALESCE(SUM(COALESCE(invoice_value, total_inv_value)),0)       AS total_inv_value,
      COALESCE(SUM(quantity),0)                                       AS total_qty,
      COUNT(DISTINCT to_party)                                        AS unique_parties,
      COUNT(DISTINCT to_place)                                        AS unique_destinations
    FROM ewbs
  `);
  res.json({ ok: true, data: s });
});

// ── Fetch log ─────────────────────────────────
app.get('/api/fetch-log', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM fetch_log ORDER BY fetched_at DESC LIMIT 20'
  );
  res.json({ ok: true, data: rows });
});

// ── CSV export ────────────────────────────────
app.get('/api/export/csv', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM ewbs ORDER BY ewb_date DESC NULLS LAST');
  const cols = ['id','ewb_no','invoice_no','invoice_date','ewb_date','ewb_status',
    'valid_upto','from_party','to_party','to_place','material','quantity','qty_unit',
    'taxable_amt','igst_amt','total_inv_value','vehicle_no',
    'rate','amount','igst_entered','invoice_value',
    'vstatus','reached_date','ulstatus','ul_date','remarks'];
  const csv = [
    cols.join(','),
    ...rows.map(r => cols.map(c => `"${(r[c]??'').toString().replace(/"/g,'""')}"`).join(','))
  ].join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="ewb_export.csv"');
  res.send(csv);
});

// ─────────────────────────────────────────────
//  Boot
// ─────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀  EWB MIS Backend  →  port ${PORT}`);
    console.log(`    Health:  http://localhost:${PORT}/health\n`);
  });
}).catch(e => {
  console.error('Fatal — DB init failed:', e.message);
  process.exit(1);
});
