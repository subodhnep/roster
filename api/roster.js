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
function currentWeekMonday() {
  const t = new Date(); t.setHours(0, 0, 0, 0);
  const offset = (t.getDay() + 6) % 7; // Mon=0..Sun=6
  return isoDate(addDays(t, -offset));
}

function computeOpenFromOverride(override) {
  if (override === 'open') return true;
  if (override === 'closed') return false;
  const jsDay = new Date().getDay();
  return jsDay >= 0 && jsDay <= 4; // Sun..Thu
}
async function getWindowOverride(client, location) {
  const res = await client.query('SELECT override FROM window_overrides WHERE location=$1', [location]);
  if (res.rows.length === 0) {
    await client.query('INSERT INTO window_overrides (location, override) VALUES ($1,$2) ON CONFLICT (location) DO NOTHING', [location, 'auto']);
    return 'auto';
  }
  return res.rows[0].override;
}
async function isWindowOpenForLocation(client, location) {
  const override = await getWindowOverride(client, location);
  return computeOpenFromOverride(override);
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

// Creates the first Super Admin account the first time the app runs against
// a database with no admins yet. Migrates the old single shared password
// (if one was set under the previous version) so nothing breaks.
async function ensureSuperAdmin(client) {
  const res = await client.query('SELECT id FROM admins LIMIT 1');
  if (res.rows.length > 0) return;
  const legacy = await client.query("SELECT setting_value FROM settings WHERE setting_key='admin_password_hash'");
  const hash = (legacy.rows.length > 0 && legacy.rows[0].setting_value)
    ? legacy.rows[0].setting_value
    : await bcrypt.hash('admin123', 10);
  await client.query(
    "INSERT INTO admins (username, password_hash, role) VALUES ('admin', $1, 'super_admin') ON CONFLICT (username) DO NOTHING",
    [hash]
  );
}

function splitDepts(s) {
  return (s || '').split(',').map(x => x.trim()).filter(Boolean);
}
const DAY_NAMES = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];

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
function issueSessionCookie(res, payloadFields) {
  const secret = getSecret();
  const payload = Object.assign({}, payloadFields, { lastActivity: Date.now() });
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
  if (!payload.adminId) return null;
  if (Date.now() - payload.lastActivity > IDLE_LIMIT_MS) return null;
  return payload;
}

// Verifies the session and returns { adminId, role, locations } where
// locations is null for a super_admin (meaning "all locations") or an
// array of location names for a regular admin. Sends a 401 and returns
// null if not authorized. Locations are looked up fresh from the DB each
// call so permission changes take effect immediately, not just at login.
async function getAdminScope(req, res, client) {
  const payload = verifySession(req);
  if (!payload) {
    res.status(401).json({ success: false, error: 'Not authorized. Please log in as admin again.' });
    return null;
  }
  issueSessionCookie(res, { adminId: payload.adminId, role: payload.role, username: payload.username }); // rolling expiry
  if (payload.role === 'super_admin') {
    return { adminId: payload.adminId, role: 'super_admin', username: payload.username, locations: null };
  }
  const locRes = await client.query('SELECT location FROM admin_locations WHERE admin_id=$1', [payload.adminId]);
  return { adminId: payload.adminId, role: 'admin', username: payload.username, locations: locRes.rows.map(r => r.location) };
}

// Convenience wrapper for actions any logged-in admin (either role) can do.
async function requireAdmin(req, res, client) {
  const scope = await getAdminScope(req, res, client);
  return scope; // null already sent the 401 response
}

// For actions restricted to Super Admin only (creating admins, managing
// departments/locations globally, etc).
async function requireSuperAdmin(req, res, client) {
  const scope = await getAdminScope(req, res, client);
  if (!scope) return null; // 401 already sent
  if (scope.role !== 'super_admin') {
    res.status(403).json({ success: false, error: 'Only a Super Admin can do that.' });
    return null;
  }
  return scope;
}

/* ============================= Handler ============================= */
module.exports = async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      res.status(405).json({ success: false, error: 'Method not allowed. This endpoint expects POST requests from the app.' });
      return;
    }

    let pool;
    try {
      pool = getPool();
    } catch (e) {
      res.status(500).json({ success: false, error: 'Failed to configure database connection: ' + e.message });
      return;
    }

    let client;
    try {
      client = await pool.connect();
    } catch (e) {
      res.status(500).json({ success: false, error: 'Database connection failed: ' + e.message });
      return;
    }

    try {
      const body = req.body || {};
      const action = body.action;

      switch (action) {

        case 'init': {
          await ensureAdminPassword(client);
          await ensureSuperAdmin(client);
          const deptRes = await client.query('SELECT name FROM departments ORDER BY id');
          const locRes = await client.query('SELECT name FROM locations ORDER BY id');
          const locationNames = locRes.rows.map(r => r.name);
          const windowStatuses = {};
          for (const loc of locationNames) {
            const override = await getWindowOverride(client, loc);
            windowStatuses[loc] = { open: computeOpenFromOverride(override), override };
          }
          return res.status(200).json({
            success: true,
            departments: deptRes.rows.map(r => r.name),
            locations: locationNames,
            windowStatuses: windowStatuses,
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
        await ensureSuperAdmin(client);
        const username = (body.username || '').trim();
        const pw = body.password || '';
        if (!username) return res.status(200).json({ success: false, error: 'Username required.' });
        const result = await client.query('SELECT id, password_hash, role FROM admins WHERE LOWER(username)=LOWER($1)', [username]);
        if (result.rows.length === 0) return res.status(200).json({ success: false, error: 'Incorrect username or password.' });
        const admin = result.rows[0];
        const ok = await bcrypt.compare(pw, admin.password_hash);
        if (!ok) return res.status(200).json({ success: false, error: 'Incorrect username or password.' });

        let locations = null;
        if (admin.role !== 'super_admin') {
          const locRes = await client.query('SELECT location FROM admin_locations WHERE admin_id=$1', [admin.id]);
          locations = locRes.rows.map(r => r.location);
        }
        issueSessionCookie(res, { adminId: admin.id, role: admin.role, username });
        return res.status(200).json({ success: true, role: admin.role, locations, username });
      }

      case 'admin_logout': {
        clearSessionCookie(res);
        return res.status(200).json({ success: true });
      }

      case 'change_admin_password': {
        const scope = await requireAdmin(req, res, client);
        if (!scope) return;
        const pw = body.newPassword || '';
        if (pw.length < 4) return res.status(200).json({ success: false, error: 'Use at least 4 characters.' });
        const hash = await bcrypt.hash(pw, 10);
        await client.query('UPDATE admins SET password_hash=$1 WHERE id=$2', [hash, scope.adminId]);
        return res.status(200).json({ success: true });
      }

      case 'set_window_override': {
        const scope = await requireAdmin(req, res, client);
        if (!scope) return;
        const location = (body.location || '').trim();
        const mode = body.mode || 'auto';
        if (!location) return res.status(200).json({ success: false, error: 'Location required.' });
        if (!['auto', 'open', 'closed'].includes(mode)) return res.status(200).json({ success: false, error: 'Invalid mode.' });
        if (scope.role !== 'super_admin' && !scope.locations.includes(location)) {
          return res.status(200).json({ success: false, error: 'You are not permitted to change the window for that location.' });
        }
        await client.query(
          'INSERT INTO window_overrides (location, override) VALUES ($1,$2) ON CONFLICT (location) DO UPDATE SET override=EXCLUDED.override',
          [location, mode]
        );
        return res.status(200).json({ success: true, location, windowOpen: computeOpenFromOverride(mode), windowOverride: mode });
      }

      case 'get_staff_list': {
        const scope = await requireAdmin(req, res, client);
        if (!scope) return;
        let result;
        if (scope.role === 'super_admin') {
          result = await client.query('SELECT id, name, departments, location, code FROM staff ORDER BY name');
        } else {
          result = await client.query('SELECT id, name, departments, location, code FROM staff WHERE location = ANY($1) ORDER BY name', [scope.locations]);
        }
        const staff = result.rows.map(r => ({ ...r, departments: splitDepts(r.departments) }));
        return res.status(200).json({ success: true, staff });
      }

      case 'add_staff': {
        const scope = await requireAdmin(req, res, client);
        if (!scope) return;
        const name = (body.name || '').trim();
        const depts = Array.isArray(body.departments) ? body.departments : [];
        const location = (body.location || '').trim();
        let code = (body.code || '').trim().toUpperCase();
        if (!name) return res.status(200).json({ success: false, error: 'Name required.' });
        if (depts.length === 0) return res.status(200).json({ success: false, error: 'Select at least one department.' });
        if (!location) return res.status(200).json({ success: false, error: 'Select a location.' });
        if (scope.role !== 'super_admin' && !scope.locations.includes(location)) {
          return res.status(200).json({ success: false, error: 'You are not permitted to add staff to that location.' });
        }

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
        const scope = await requireAdmin(req, res, client);
        if (!scope) return;
        const id = parseInt(body.id, 10) || 0;
        if (scope.role !== 'super_admin') {
          const chk = await client.query('SELECT location FROM staff WHERE id=$1', [id]);
          if (chk.rows.length === 0) return res.status(200).json({ success: true }); // already gone
          if (!scope.locations.includes(chk.rows[0].location)) {
            return res.status(200).json({ success: false, error: 'You are not permitted to remove staff from that location.' });
          }
        }
        await client.query('DELETE FROM staff WHERE id=$1', [id]);
        return res.status(200).json({ success: true });
      }

      case 'add_department': {
        if (!(await requireSuperAdmin(req, res, client))) return;
        const name = (body.name || '').trim();
        if (!name) return res.status(200).json({ success: false, error: 'Name required.' });
        await client.query('INSERT INTO departments (name) VALUES ($1) ON CONFLICT (name) DO NOTHING', [name]);
        return res.status(200).json({ success: true });
      }

      case 'remove_department': {
        if (!(await requireSuperAdmin(req, res, client))) return;
        const name = (body.name || '').trim();
        await client.query('DELETE FROM departments WHERE name=$1', [name]);
        return res.status(200).json({ success: true });
      }

      case 'add_location': {
        if (!(await requireSuperAdmin(req, res, client))) return;
        const name = (body.name || '').trim();
        if (!name) return res.status(200).json({ success: false, error: 'Name required.' });
        await client.query('INSERT INTO locations (name) VALUES ($1) ON CONFLICT (name) DO NOTHING', [name]);
        return res.status(200).json({ success: true });
      }

      case 'remove_location': {
        if (!(await requireSuperAdmin(req, res, client))) return;
        const name = (body.name || '').trim();
        await client.query('DELETE FROM locations WHERE name=$1', [name]);
        return res.status(200).json({ success: true });
      }

      case 'list_admins': {
        if (!(await requireSuperAdmin(req, res, client))) return;
        const result = await client.query('SELECT id, username, role, created_at FROM admins ORDER BY created_at');
        const admins = [];
        for (const a of result.rows) {
          let locations = null;
          if (a.role !== 'super_admin') {
            const locRes = await client.query('SELECT location FROM admin_locations WHERE admin_id=$1', [a.id]);
            locations = locRes.rows.map(r => r.location);
          }
          admins.push({ id: a.id, username: a.username, role: a.role, locations, createdAt: a.created_at });
        }
        return res.status(200).json({ success: true, admins });
      }

      case 'create_admin': {
        if (!(await requireSuperAdmin(req, res, client))) return;
        const username = (body.username || '').trim();
        const password = body.password || '';
        const role = body.role === 'super_admin' ? 'super_admin' : 'admin';
        const locations = Array.isArray(body.locations) ? body.locations : [];
        if (!username) return res.status(200).json({ success: false, error: 'Username required.' });
        if (password.length < 4) return res.status(200).json({ success: false, error: 'Password must be at least 4 characters.' });
        if (role === 'admin' && locations.length === 0) {
          return res.status(200).json({ success: false, error: 'Select at least one location for this admin.' });
        }
        const exists = await client.query('SELECT id FROM admins WHERE LOWER(username)=LOWER($1)', [username]);
        if (exists.rows.length > 0) return res.status(200).json({ success: false, error: 'That username is already taken.' });

        const hash = await bcrypt.hash(password, 10);
        const ins = await client.query('INSERT INTO admins (username, password_hash, role) VALUES ($1,$2,$3) RETURNING id', [username, hash, role]);
        const newId = ins.rows[0].id;
        if (role === 'admin') {
          for (const loc of locations) {
            await client.query('INSERT INTO admin_locations (admin_id, location) VALUES ($1,$2) ON CONFLICT DO NOTHING', [newId, loc]);
          }
        }
        return res.status(200).json({ success: true, id: newId });
      }

      case 'remove_admin': {
        const scope = await requireSuperAdmin(req, res, client);
        if (!scope) return;
        const id = parseInt(body.id, 10) || 0;
        if (id === scope.adminId) return res.status(200).json({ success: false, error: 'You can\u2019t remove your own account while logged in as it.' });
        const countRes = await client.query("SELECT COUNT(*)::int AS c FROM admins WHERE role='super_admin'");
        const target = await client.query('SELECT role FROM admins WHERE id=$1', [id]);
        if (target.rows.length > 0 && target.rows[0].role === 'super_admin' && countRes.rows[0].c <= 1) {
          return res.status(200).json({ success: false, error: 'Can\u2019t remove the last Super Admin.' });
        }
        await client.query('DELETE FROM admins WHERE id=$1', [id]);
        return res.status(200).json({ success: true });
      }

      case 'set_admin_locations': {
        if (!(await requireSuperAdmin(req, res, client))) return;
        const id = parseInt(body.id, 10) || 0;
        const locations = Array.isArray(body.locations) ? body.locations : [];
        await client.query('DELETE FROM admin_locations WHERE admin_id=$1', [id]);
        for (const loc of locations) {
          await client.query('INSERT INTO admin_locations (admin_id, location) VALUES ($1,$2) ON CONFLICT DO NOTHING', [id, loc]);
        }
        return res.status(200).json({ success: true });
      }

      case 'reset_admin_password': {
        if (!(await requireSuperAdmin(req, res, client))) return;
        const id = parseInt(body.id, 10) || 0;
        const password = body.password || '';
        if (password.length < 4) return res.status(200).json({ success: false, error: 'Password must be at least 4 characters.' });
        const hash = await bcrypt.hash(password, 10);
        await client.query('UPDATE admins SET password_hash=$1 WHERE id=$2', [hash, id]);
        return res.status(200).json({ success: true });
      }

      case 'list_weeks': {
        const scope = await requireAdmin(req, res, client);
        if (!scope) return;
        const result = await client.query('SELECT DISTINCT week_start::text AS week_start FROM availability ORDER BY week_start DESC LIMIT 2');
        let weeks = result.rows.map(r => r.week_start);
        const target = targetWeekStart();
        if (!weeks.includes(target)) weeks.unshift(target);
        weeks = Array.from(new Set(weeks)).sort().reverse();
        return res.status(200).json({ success: true, weeks, targetWeekStart: target });
      }

      case 'get_availability': {
        const scope = await requireAdmin(req, res, client);
        if (!scope) return;
        const weekStart = body.weekStart;
        if (!weekStart) return res.status(200).json({ success: false, error: 'weekStart required.' });
        let result;
        if (scope.role === 'super_admin') {
          result = await client.query(
            `SELECT a.staff_id, a.day, a.available, a.start_time, a.end_time, a.submitted_at, s.name, s.departments, s.location
             FROM availability a JOIN staff s ON s.id = a.staff_id
             WHERE a.week_start = $1::date`,
            [weekStart]
          );
        } else {
          result = await client.query(
            `SELECT a.staff_id, a.day, a.available, a.start_time, a.end_time, a.submitted_at, s.name, s.departments, s.location
             FROM availability a JOIN staff s ON s.id = a.staff_id
             WHERE a.week_start = $1::date AND s.location = ANY($2)`,
            [weekStart, scope.locations]
          );
        }
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

        const staffRow = await client.query('SELECT location FROM staff WHERE id=$1', [staffId]);
        if (staffRow.rows.length === 0) return res.status(200).json({ success: false, error: 'Staff record not found.' });
        const location = staffRow.rows[0].location;

        const open = await isWindowOpenForLocation(client, location);
        if (!open) return res.status(200).json({ success: false, error: 'The availability window is closed for your location. It reopens Sunday and closes Thursday night, unless your admin has changed this.' });
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

      case 'publish_roster': {
        const scope = await requireAdmin(req, res, client);
        if (!scope) return;
        const weekStart = body.weekStart;
        let entries = Array.isArray(body.entries) ? body.entries : [];
        if (!weekStart) return res.status(200).json({ success: false, error: 'weekStart required.' });
        if (entries.length === 0) return res.status(200).json({ success: false, error: 'No matched staff rows to publish.' });

        if (scope.role !== 'super_admin') {
          const ids = entries.map(e => parseInt(e.staffId, 10)).filter(Boolean);
          const ownedRes = await client.query('SELECT id FROM staff WHERE id = ANY($1) AND location = ANY($2)', [ids, scope.locations]);
          const ownedIds = new Set(ownedRes.rows.map(r => String(r.id)));
          entries = entries.filter(e => ownedIds.has(String(e.staffId)));
          if (entries.length === 0) {
            return res.status(200).json({ success: false, error: 'None of those staff belong to your assigned location(s).' });
          }
        }

        for (const entry of entries) {
          const staffId = parseInt(entry.staffId, 10) || 0;
          if (!staffId) continue;
          const days = entry.days || {};
          for (const dayName of DAY_NAMES) {
            const text = (days[dayName] || '').toString().trim();
            await client.query(
              `INSERT INTO roster_shifts (staff_id, week_start, day, shift_text)
               VALUES ($1,$2::date,$3,$4)
               ON CONFLICT (staff_id, week_start, day)
               DO UPDATE SET shift_text=EXCLUDED.shift_text`,
              [staffId, weekStart, dayName, text]
            );
          }
        }
        await client.query(
          `INSERT INTO roster_meta (week_start, published, published_at) VALUES ($1::date, TRUE, NOW())
           ON CONFLICT (week_start) DO UPDATE SET published=TRUE, published_at=NOW()`,
          [weekStart]
        );

        // Retention: keep exactly the two weeks staff can actually see -
        // the currently running week and next week - regardless of the
        // order they were published in. (Publishing next week's roster
        // early, while this week is still running, must not wipe out
        // this week's still-relevant published shifts.)
        const keep = Array.from(new Set([currentWeekMonday(), targetWeekStart(), weekStart]));
        if (keep.length > 0) {
          const placeholders = keep.map((_, i) => `$${i + 1}::date`).join(',');
          await client.query(`DELETE FROM roster_shifts WHERE week_start NOT IN (${placeholders})`, keep);
          await client.query(`DELETE FROM roster_meta WHERE week_start NOT IN (${placeholders})`, keep);
        }

        return res.status(200).json({ success: true, weekStart, count: entries.length });
      }

      case 'unpublish_roster': {
        const scope = await requireAdmin(req, res, client);
        if (!scope) return;
        const weekStart = body.weekStart;
        if (!weekStart) return res.status(200).json({ success: false, error: 'weekStart required.' });

        if (scope.role === 'super_admin') {
          await client.query('DELETE FROM roster_shifts WHERE week_start=$1::date', [weekStart]);
          await client.query('DELETE FROM roster_meta WHERE week_start=$1::date', [weekStart]);
        } else {
          await client.query(
            `DELETE FROM roster_shifts WHERE week_start=$1::date AND staff_id IN (SELECT id FROM staff WHERE location = ANY($2))`,
            [weekStart, scope.locations]
          );
          const remaining = await client.query('SELECT 1 FROM roster_shifts WHERE week_start=$1::date LIMIT 1', [weekStart]);
          if (remaining.rows.length === 0) {
            await client.query('DELETE FROM roster_meta WHERE week_start=$1::date', [weekStart]);
          }
        }
        return res.status(200).json({ success: true });
      }

      case 'get_roster': {
        const scope = await requireAdmin(req, res, client);
        if (!scope) return;
        const weekStart = body.weekStart;
        if (!weekStart) return res.status(200).json({ success: false, error: 'weekStart required.' });
        const metaRes = await client.query('SELECT published, published_at FROM roster_meta WHERE week_start=$1::date', [weekStart]);
        const published = metaRes.rows.length > 0 && metaRes.rows[0].published;
        let result;
        if (scope.role === 'super_admin') {
          result = await client.query(
            `SELECT rs.staff_id, rs.day, rs.shift_text, s.name, s.location, s.departments
             FROM roster_shifts rs JOIN staff s ON s.id = rs.staff_id
             WHERE rs.week_start = $1::date`,
            [weekStart]
          );
        } else {
          result = await client.query(
            `SELECT rs.staff_id, rs.day, rs.shift_text, s.name, s.location, s.departments
             FROM roster_shifts rs JOIN staff s ON s.id = rs.staff_id
             WHERE rs.week_start = $1::date AND s.location = ANY($2)`,
            [weekStart, scope.locations]
          );
        }
        const byStaff = {};
        for (const row of result.rows) {
          const sid = String(row.staff_id);
          if (!byStaff[sid]) {
            byStaff[sid] = { staffId: sid, name: row.name, location: row.location, departments: splitDepts(row.departments), days: {} };
          }
          byStaff[sid].days[row.day] = row.shift_text || '';
        }
        return res.status(200).json({ success: true, weekStart, published, data: Object.values(byStaff) });
      }

      case 'get_my_roster': {
        const staffId = parseInt(body.staffId, 10) || 0;
        const weekStart = body.weekStart;
        if (!staffId || !weekStart) return res.status(200).json({ success: false, error: 'Missing data.' });
        const metaRes = await client.query('SELECT published FROM roster_meta WHERE week_start=$1::date', [weekStart]);
        const published = metaRes.rows.length > 0 && metaRes.rows[0].published;
        if (!published) return res.status(200).json({ success: true, published: false, days: {} });
        const result = await client.query(
          'SELECT day, shift_text FROM roster_shifts WHERE staff_id=$1 AND week_start=$2::date',
          [staffId, weekStart]
        );
        const days = {};
        for (const row of result.rows) days[row.day] = row.shift_text || '';
        return res.status(200).json({ success: true, published: true, days });
      }

      default:
        return res.status(200).json({ success: false, error: 'Unknown action.' });
      }
    } catch (e) {
      return res.status(500).json({ success: false, error: 'Server error: ' + e.message });
    } finally {
      client.release();
    }
  } catch (outerErr) {
    // Absolute last resort - guarantees we never crash without sending a response.
    try {
      res.status(500).json({ success: false, error: 'Unexpected server error: ' + outerErr.message });
    } catch (e2) { /* response already sent */ }
  }
};
