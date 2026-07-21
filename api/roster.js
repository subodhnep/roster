const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Reused across warm invocations of this function.
let pool;
function getPool() {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL || process.env.POSTGRES_URL,
      ssl: { rejectUnauthorized: false }
    });
  }
  return pool;
}

/* ============================= Date / window helpers ============================= */
function pad(n) { return n < 10 ? '0' + n : '' + n; }
function isoDate(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); }
function addDays(d, n) { const r = new Date(d); r.setDate(r.getDate() + n); return r; }

// The Thursday that anchors the currently-open (or most recently closed) Sun-Thu window.
function referenceThursday() {
  const t = new Date(); t.setHours(0, 0, 0, 0);
  const jsDay = t.getDay(); // Sun=0..Sat=6
  if (jsDay <= 4) return addDays(t, 4 - jsDay);
  return addDays(t, -(jsDay - 4));
}
function targetWeekStart() { return isoDate(addDays(referenceThursday(), 4)); } // Thu -> Mon

async function getWindowOverride(client) {
  const res = await client.query("SELECT setting_value FROM settings WHERE setting_key='window_override'");
  if (res.rows.length === 0) {
    await client.query("INSERT INTO settings (setting_key, setting_value) VALUES ('window_override','auto') ON CONFLICT (setting_key) DO NOTHING");
    return 'auto';
  }
  return res.rows[0].setting_value;
}
async function isWindowOpen(client) {
  const override = await getWindowOverride(client);
  if (override === 'open') return true;
  if (override === 'closed') return false;
  const jsDay = new Date().getDay();
  return jsDay >= 0 && jsDay <= 4; // Sun..Thu
}

async function ensureAdminPassword(client) {
  const res = await client.query("SELECT setting_value FROM settings WHERE setting_key='admin_password_hash'");
  if (res.rows.length === 0 || !res.rows[0].setting_value) {
    const hash = await bcrypt.hash('admin123', 10);
    await client.query(
      "INSERT INTO settings (setting_key, setting_value) VALUES ('admin_password_hash',$1) ON CONFLICT (setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value",
      [hash]
    );
  }
}

function splitDepts(s) {
  return (s || '').split(',').map(x => x.trim()).filter(Boolean);
}

/* ============================= Cookie-based admin session ============================= */
const IDLE_LIMIT_MS = 15 * 60 * 1000;

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}
function getSecret() {
  return process.env.ADMIN_SESSION_SECRET || 'change-me-in-vercel-env-vars';
}
function issueSessionCookie(res) {
  const secret = getSecret();
  const payload = { isAdmin: true, lastActivity: Date.now() };
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  const token = data + '.' + mac;
  res.setHeader('Set-Cookie', `admin_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=900`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `admin_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
}
function verifySession(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const token = cookies['admin_session'];
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [data, mac] = parts;
  const expected = crypto.createHmac('sha256', getSecret()).update(data).digest('base64url');
  if (mac !== expected) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8')); }
  catch (e) { return null; }
  if (!payload.isAdmin) return null;
  if (Date.now() - payload.lastActivity > IDLE_LIMIT_MS) return null;
  return payload;
}
// Returns true and slides the session forward if valid; sends a 401 JSON response and returns false otherwise.
function requireAdmin(req, res) {
  const payload = verifySession(req);
  if (!payload) {
    res.status(401).json({ success: false, error: 'Not authorized. Please log in as admin again.' });
    return false;
  }
  issueSessionCookie(res); // rolling expiry
  return true;
}

/* ============================= Handler ============================= */
module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ success: false, error: 'Method not allowed. This endpoint expects POST requests from the app.' });
    return;
  }

  const pool = getPool();
  const client = await pool.connect();
  try {
    const body = req.body || {};
    const action = body.action;

    switch (action) {

      case 'init': {
        await ensureAdminPassword(client);
        const deptRes = await client.query('SELECT name FROM departments ORDER BY id');
        const locRes = await client.query('SELECT name FROM locations ORDER BY id');
        const override = await getWindowOverride(client);
        const open = await isWindowOpen(client);
        return res.status(200).json({
          success: true,
          departments: deptRes.rows.map(r => r.name),
          locations: locRes.rows.map(r => r.name),
          windowOpen: open,
          windowOverride: override,
          targetWeekStart: targetWeekStart()
        });
      }

      case 'staff_login': {
        const code = (body.code || '').trim().toUpperCase();
        if (!code) return res.status(200).json({ success: false, error: 'Code required' });
        const result = await client.query('SELECT id, name, departments, location, code FROM staff WHERE UPPER(code)=$1', [code]);
        if (result.rows.length === 0) return res.status(200).json({ success: false, error: 'That code was not recognised. Check with your admin.' });
        const row = result.rows[0];
        row.departments = splitDepts(row.departments);
        return res.status(200).json({ success: true, staff: row });
      }

      case 'admin_login': {
        const pw = body.password || '';
        await ensureAdminPassword(client);
        const result = await client.query("SELECT setting_value FROM settings WHERE setting_key='admin_password_hash'");
        const hash = result.rows[0] ? result.rows[0].setting_value : null;
        const ok = hash ? await bcrypt.compare(pw, hash) : false;
        if (!ok) return res.status(200).json({ success: false, error: 'Incorrect password.' });
        issueSessionCookie(res);
        return res.status(200).json({ success: true });
      }

      case 'admin_logout': {
        clearSessionCookie(res);
        return res.status(200).json({ success: true });
      }

      case 'change_admin_password': {
        if (!requireAdmin(req, res)) return;
        const pw = body.newPassword || '';
        if (pw.length < 4) return res.status(200).json({ success: false, error: 'Use at least 4 characters.' });
        const hash = await bcrypt.hash(pw, 10);
        await client.query(
          "INSERT INTO settings (setting_key, setting_value) VALUES ('admin_password_hash',$1) ON CONFLICT (setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value",
          [hash]
        );
        return res.status(200).json({ success: true });
      }

      case 'set_window_override': {
        if (!requireAdmin(req, res)) return;
        const mode = body.mode || 'auto';
        if (!['auto', 'open', 'closed'].includes(mode)) return res.status(200).json({ success: false, error: 'Invalid mode.' });
        await client.query(
          "INSERT INTO settings (setting_key, setting_value) VALUES ('window_override',$1) ON CONFLICT (setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value",
          [mode]
        );
        const open = await isWindowOpen(client);
        return res.status(200).json({ success: true, windowOpen: open, windowOverride: mode });
      }

      case 'get_staff_list': {
        if (!requireAdmin(req, res)) return;
        const result = await client.query('SELECT id, name, departments, location, code FROM staff ORDER BY name');
        const staff = result.rows.map(r => ({ ...r, departments: splitDepts(r.departments) }));
        return res.status(200).json({ success: true, staff });
      }

      case 'add_staff': {
        if (!requireAdmin(req, res)) return;
        const name = (body.name || '').trim();
        const depts = Array.isArray(body.departments) ? body.departments : [];
        const location = (body.location || '').trim();
        let code = (body.code || '').trim().toUpperCase();
        if (!name) return res.status(200).json({ success: false, error: 'Name required.' });
        if (depts.length === 0) return res.status(200).json({ success: false, error: 'Select at least one department.' });
        if (!location) return res.status(200).json({ success: false, error: 'Select a location.' });

        if (!code) {
          const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
          let exists = true;
          while (exists) {
            code = '';
            for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
            const chk = await client.query('SELECT id FROM staff WHERE UPPER(code)=$1', [code]);
            exists = chk.rows.length > 0;
          }
        } else {
          const chk = await client.query('SELECT id FROM staff WHERE UPPER(code)=$1', [code]);
          if (chk.rows.length > 0) return res.status(200).json({ success: false, error: 'That code is already in use.' });
        }

        const deptStr = depts.map(d => d.trim()).join(',');
        const ins = await client.query(
          'INSERT INTO staff (name, departments, location, code) VALUES ($1,$2,$3,$4) RETURNING id',
          [name, deptStr, location, code]
        );
        return res.status(200).json({ success: true, id: ins.rows[0].id, code });
      }

      case 'remove_staff': {
        if (!requireAdmin(req, res)) return;
        const id = parseInt(body.id, 10) || 0;
        await client.query('DELETE FROM staff WHERE id=$1', [id]);
        return res.status(200).json({ success: true });
      }

      case 'add_department': {
        if (!requireAdmin(req, res)) return;
        const name = (body.name || '').trim();
        if (!name) return res.status(200).json({ success: false, error: 'Name required.' });
        await client.query('INSERT INTO departments (name) VALUES ($1) ON CONFLICT (name) DO NOTHING', [name]);
        return res.status(200).json({ success: true });
      }

      case 'remove_department': {
        if (!requireAdmin(req, res)) return;
        const name = (body.name || '').trim();
        await client.query('DELETE FROM departments WHERE name=$1', [name]);
        return res.status(200).json({ success: true });
      }

      case 'add_location': {
        if (!requireAdmin(req, res)) return;
        const name = (body.name || '').trim();
        if (!name) return res.status(200).json({ success: false, error: 'Name required.' });
        await client.query('INSERT INTO locations (name) VALUES ($1) ON CONFLICT (name) DO NOTHING', [name]);
        return res.status(200).json({ success: true });
      }

      case 'remove_location': {
        if (!requireAdmin(req, res)) return;
        const name = (body.name || '').trim();
        await client.query('DELETE FROM locations WHERE name=$1', [name]);
        return res.status(200).json({ success: true });
      }

      case 'list_weeks': {
        if (!requireAdmin(req, res)) return;
        const result = await client.query('SELECT DISTINCT week_start::text AS week_start FROM availability ORDER BY week_start DESC LIMIT 2');
        let weeks = result.rows.map(r => r.week_start);
        const target = targetWeekStart();
        if (!weeks.includes(target)) weeks.unshift(target);
        weeks = Array.from(new Set(weeks)).sort().reverse();
        return res.status(200).json({ success: true, weeks, targetWeekStart: target });
      }

      case 'get_availability': {
        if (!requireAdmin(req, res)) return;
        const weekStart = body.weekStart;
        if (!weekStart) return res.status(200).json({ success: false, error: 'weekStart required.' });
        const result = await client.query(
          `SELECT a.staff_id, a.day, a.available, a.start_time, a.end_time, a.submitted_at, s.name, s.departments, s.location
           FROM availability a JOIN staff s ON s.id = a.staff_id
           WHERE a.week_start = $1::date`,
          [weekStart]
        );
        const byStaff = {};
        for (const row of result.rows) {
          const sid = String(row.staff_id);
          if (!byStaff[sid]) {
            byStaff[sid] = {
              staffId: sid,
              name: row.name,
              departments: splitDepts(row.departments),
              location: row.location,
              submittedAt: row.submitted_at,
              days: {}
            };
          }
          byStaff[sid].days[row.day] = { available: row.available, start: row.start_time, end: row.end_time };
        }
        return res.status(200).json({ success: true, weekStart, data: Object.values(byStaff) });
      }

      case 'get_my_availability': {
        const staffId = parseInt(body.staffId, 10) || 0;
        const weekStart = body.weekStart;
        if (!staffId || !weekStart) return res.status(200).json({ success: false, error: 'Missing data.' });
        const result = await client.query(
          'SELECT day, available, start_time, end_time FROM availability WHERE staff_id=$1 AND week_start=$2::date',
          [staffId, weekStart]
        );
        const days = {};
        for (const row of result.rows) {
          days[row.day] = { available: row.available, start: row.start_time, end: row.end_time };
        }
        return res.status(200).json({ success: true, days });
      }

      case 'set_availability': {
        const staffId = parseInt(body.staffId, 10) || 0;
        const weekStart = body.weekStart;
        const days = body.days || {};
        if (!staffId || !weekStart) return res.status(200).json({ success: false, error: 'Missing data.' });

        const open = await isWindowOpen(client);
        if (!open) return res.status(200).json({ success: false, error: 'The availability window is closed. It reopens Sunday and closes Thursday night.' });
        if (weekStart !== targetWeekStart()) return res.status(200).json({ success: false, error: 'This week is no longer open for submissions.' });

        for (const [dayName, d] of Object.entries(days)) {
          const available = !!(d && d.available);
          const start = available ? (d.start || null) : null;
          const end = available ? (d.end || null) : null;
          await client.query(
            `INSERT INTO availability (staff_id, week_start, day, available, start_time, end_time, submitted_at)
             VALUES ($1,$2::date,$3,$4,$5,$6,NOW())
             ON CONFLICT (staff_id, week_start, day)
             DO UPDATE SET available=EXCLUDED.available, start_time=EXCLUDED.start_time, end_time=EXCLUDED.end_time, submitted_at=NOW()`,
            [staffId, weekStart, dayName, available, start, end]
          );
        }

        // Retention: keep only the 2 most recent weeks of availability data.
        const keepRes = await client.query('SELECT DISTINCT week_start::text AS week_start FROM availability ORDER BY week_start DESC LIMIT 2');
        const keep = keepRes.rows.map(r => r.week_start);
        if (keep.length > 0) {
          const placeholders = keep.map((_, i) => `$${i + 1}::date`).join(',');
          await client.query(`DELETE FROM availability WHERE week_start NOT IN (${placeholders})`, keep);
        }

        return res.status(200).json({ success: true });
      }

      default:
        return res.status(200).json({ success: false, error: 'Unknown action.' });
    }
  } catch (e) {
    return res.status(500).json({ success: false, error: 'Server error: ' + e.message });
  } finally {
    client.release();
  }
};
