'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const XLSX = require('xlsx');
const Database = require('better-sqlite3');

const PORT = Number(process.env.PORT) || 3000;
const HOST = '0.0.0.0';
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const MAX_UPLOAD = 10 * 1024 * 1024;
const SESSION_MS = 12 * 60 * 60 * 1000;
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'achievements.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','viewer')),
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  match_key TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS uploads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL,
  record_date TEXT NOT NULL,
  file_hash TEXT NOT NULL,
  rows_count INTEGER NOT NULL,
  total REAL NOT NULL DEFAULT 0,
  uploaded_by TEXT,
  uploaded_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS achievements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  record_date TEXT NOT NULL,
  value REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ach_emp ON achievements(employee_id);
CREATE INDEX IF NOT EXISTS idx_ach_date ON achievements(record_date);
`);

// ---------- helpers ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function verifyPassword(pw, stored) {
  const [salt, h] = String(stored).split(':');
  if (!salt || !h) return false;
  const test = crypto.scryptSync(pw, salt, 64);
  const ref = Buffer.from(h, 'hex');
  return ref.length === test.length && crypto.timingSafeEqual(ref, test);
}
function httpError(status, message, extra) {
  const e = new Error(message);
  e.status = status;
  if (extra) e.extra = extra;
  return e;
}
function round2(n) { return Math.round((Number(n) || 0) * 100) / 100; }
function isDate(s) { return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s + 'T00:00:00Z')); }
function safeName(s) { return path.basename(String(s)).replace(/[\r\n"]/g, '').slice(0, 150) || 'file.xlsx'; }

// ---------- initial owner account ----------
const adminCount = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role='admin'").get().c;
if (!adminCount) {
  const username = process.env.ADMIN_USER || 'owner';
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(6).toString('base64url');
  db.prepare("INSERT INTO users(username,display_name,password_hash,role) VALUES(?,?,?,'admin')")
    .run(username, 'المالك', hashPassword(pw));
  const msg = `Initial owner account: username=${username} password=${pw}`;
  fs.writeFileSync(path.join(DATA_DIR, 'initial-owner.txt'),
    msg + '\nغيّر كلمة المرور من الصفحة المخفية ثم احذف هذا الملف.\n');
  console.log(msg);
}

// ---------- sessions & rate limit ----------
const sessions = new Map(); // sid -> session
const fails = new Map();    // ip -> {count, lockUntil}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}
function getSession(req) {
  const sid = parseCookies(req).sid;
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (s.exp < Date.now()) { sessions.delete(sid); return null; }
  return s;
}
function createSession(user) {
  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, {
    userId: user.id, username: user.username, display: user.display_name,
    role: user.role, exp: Date.now() + SESSION_MS
  });
  return `sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}`;
}

// ---------- io ----------
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml'
};
function sendJson(res, status, obj, extra = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra });
  res.end(JSON.stringify(obj));
}
function sendFile(res, rel) {
  const full = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!full.startsWith(PUBLIC_DIR + path.sep)) return sendJson(res, 404, { error: 'not found' });
  fs.readFile(full, (err, data) => {
    if (err) return sendJson(res, 404, { error: 'not found' });
    res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream', 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff' });
    res.end(data);
  });
}
function redirect(res, location) { res.writeHead(302, { Location: location }); res.end(); }
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > limit) { req.destroy(); return reject(httpError(413, 'حجم الملف أو البيانات كبير جدا')); }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJson(req) {
  const b = await readBody(req, 100000);
  if (!b.length) return {};
  try { return JSON.parse(b.toString('utf8')); } catch { throw httpError(400, 'بيانات غير صالحة'); }
}

// ---------- excel parsing ----------
function normKey(s) {
  return s.replace(/[إأآ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه')
    .replace(/\s+/g, ' ').trim().toLowerCase();
}
function toNumber(v) {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const t = v.replace(/[,\s٬]/g, '').replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d));
    const n = Number(t);
    return t !== '' && isFinite(n) ? n : NaN;
  }
  return NaN;
}
function parseWorkbook(buf) {
  const wb = XLSX.read(buf, { type: 'buffer' });
  const ws = wb.Sheets[wb.SheetNames[0]];
  const grid = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '', raw: true });
  let nameCol = -1, valCol = -1, start = 0;
  for (let i = 0; i < Math.min(grid.length, 30); i++) {
    let nc = -1, vc = -1;
    grid[i].forEach((c, j) => {
      const s = String(c).trim();
      if (nc < 0 && /(اسم|الموظف|الموظفين|name|employee)/i.test(s)) nc = j;
      if (vc < 0 && /(منجز|انجاز|إنجاز|عدد|achiev|count)/i.test(s)) vc = j;
    });
    if (nc >= 0 && vc >= 0) { nameCol = nc; valCol = vc; start = i + 1; break; }
  }
  if (nameCol < 0) { nameCol = 0; valCol = 1; start = 0; }

  const map = new Map();
  for (let i = start; i < grid.length; i++) {
    const row = grid[i];
    const name = String(row[nameCol] ?? '').replace(/\s+/g, ' ').trim();
    if (!name || /(الاجمالي|اجمالي|المجموع|total)/i.test(normKey(name))) continue;
    const val = toNumber(row[valCol]);
    if (!isFinite(val)) continue;
    const key = normKey(name);
    const cur = map.get(key) || { name, key, value: 0 };
    cur.value += val;
    map.set(key, cur);
  }
  return [...map.values()];
}

// ---------- owner & viewer data ----------
function getRange(url) {
  const f = url.searchParams.get('from'), t = url.searchParams.get('to');
  return { from: isDate(f) ? f : '0000-01-01', to: isDate(t) ? t : '9999-12-31' };
}
function summary(url) {
  const { from, to } = getRange(url);
  const employees = db.prepare(`
    SELECT e.id, e.name, ROUND(SUM(a.value),2) AS total,
           COUNT(DISTINCT a.record_date) AS days, MAX(a.record_date) AS lastDate
    FROM achievements a JOIN employees e ON e.id = a.employee_id
    WHERE a.record_date BETWEEN ? AND ?
    GROUP BY e.id ORDER BY total DESC, e.name`).all(from, to);
  const monthly = db.prepare(`
    SELECT substr(record_date,1,7) AS month, ROUND(SUM(value),2) AS total
    FROM achievements WHERE record_date BETWEEN ? AND ?
    GROUP BY month ORDER BY month`).all(from, to);
  const months = db.prepare('SELECT DISTINCT substr(record_date,1,7) AS m FROM achievements ORDER BY m').all().map(r => r.m);
  const uploads = db.prepare('SELECT COUNT(*) AS c, MAX(record_date) AS last FROM uploads WHERE record_date BETWEEN ? AND ?').get(from, to);
  const total = round2(employees.reduce((s, e) => s + e.total, 0));
  const top = employees[0] ? { id: employees[0].id, name: employees[0].name, total: employees[0].total } : null;
  return {
    range: { from, to }, months, monthly, employees,
    kpis: {
      total, employees: employees.length, uploads: uploads.c, lastUpload: uploads.last || null,
      top, average: employees.length ? round2(total / employees.length) : 0
    }
  };
}
function employeeDetail(url, id) {
  const emp = db.prepare('SELECT id, name FROM employees WHERE id = ?').get(id);
  if (!emp) throw httpError(404, 'الموظف غير موجود');
  const { from, to } = getRange(url);
  const daily = db.prepare(`
    SELECT record_date AS date, ROUND(SUM(value),2) AS total FROM achievements
    WHERE employee_id=? AND record_date BETWEEN ? AND ?
    GROUP BY record_date ORDER BY record_date`).all(id, from, to);
  const monthly = db.prepare(`
    SELECT substr(record_date,1,7) AS month, ROUND(SUM(value),2) AS total FROM achievements
    WHERE employee_id=? AND record_date BETWEEN ? AND ?
    GROUP BY month ORDER BY month`).all(id, from, to);
  return { employee: emp, total: round2(daily.reduce((s, d) => s + d.total, 0)), days: daily.length, daily, monthly };
}

// ---------- owner: uploads ----------
async function handleUpload(req, res, url, sess) {
  const date = url.searchParams.get('date');
  if (!isDate(date)) throw httpError(400, 'تاريخ الرفع غير صالح');
  let rawName = 'file.xlsx';
  try { rawName = decodeURIComponent(req.headers['x-filename'] || rawName); } catch {}
  const filename = safeName(rawName);
  if (!/\.(xlsx|xls|csv)$/i.test(filename)) throw httpError(400, 'يجب أن يكون الملف بصيغة xlsx أو xls أو csv');
  const buf = await readBody(req, MAX_UPLOAD);
  if (!buf.length) throw httpError(400, 'الملف فارغ');

  let rows;
  try { rows = parseWorkbook(buf); } catch { throw httpError(400, 'تعذر قراءة الملف، تأكد أنه ملف Excel صالح'); }
  if (!rows.length) throw httpError(400, 'لم يتم العثور على بيانات. تأكد من وجود عمود "اسم الموظف" وعمود "المنجز من قبل الموظف"');

  const hash = crypto.createHash('sha256').update(buf).digest('hex');
  const force = url.searchParams.get('force') === '1';
  const dup = db.prepare('SELECT id FROM uploads WHERE file_hash=? AND record_date=?').get(hash, date);
  if (dup && !force) throw httpError(409, 'هذا الملف مرفوع مسبقا بنفس التاريخ. هل تريد رفعه مرة أخرى؟', { duplicate: true });

  const getEmp = db.prepare('SELECT id FROM employees WHERE match_key=?');
  const addEmp = db.prepare('INSERT INTO employees(name,match_key) VALUES(?,?)');
  const addAch = db.prepare('INSERT INTO achievements(upload_id,employee_id,record_date,value) VALUES(?,?,?,?)');
  const tx = db.transaction(() => {
    const up = db.prepare('INSERT INTO uploads(filename,record_date,file_hash,rows_count,total,uploaded_by) VALUES(?,?,?,?,0,?)')
      .run(filename, date, hash, rows.length, sess.username);
    const uploadId = Number(up.lastInsertRowid);
    let newEmployees = 0, total = 0;
    for (const r of rows) {
      let e = getEmp.get(r.key);
      if (!e) { e = { id: Number(addEmp.run(r.name, r.key).lastInsertRowid) }; newEmployees++; }
      addAch.run(uploadId, e.id, date, r.value);
      total += r.value;
    }
    db.prepare('UPDATE uploads SET total=? WHERE id=?').run(round2(total), uploadId);
    return { uploadId, newEmployees, total: round2(total) };
  });
  const result = tx();
  return sendJson(res, 200, { ok: true, employees: rows.length, ...result });
}

// ---------- owner: users ----------
function listUsers() {
  return db.prepare('SELECT id, username, display_name AS displayName, role, created_at AS createdAt FROM users ORDER BY id').all();
}
async function createUser(req, res) {
  const body = await readJson(req);
  const username = String(body.username || '').trim();
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) throw httpError(400, 'اسم المستخدم بالإنجليزية أو الأرقام فقط (3 إلى 32 حرفا)');
  const password = String(body.password || '');
  if (password.length < 6) throw httpError(400, 'كلمة المرور 6 أحرف على الأقل');
  const displayName = String(body.displayName || username).trim().slice(0, 80) || username;
  const role = body.role === 'admin' ? 'admin' : 'viewer';
  try {
    db.prepare('INSERT INTO users(username,display_name,password_hash,role) VALUES(?,?,?,?)')
      .run(username, displayName, hashPassword(password), role);
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) throw httpError(409, 'اسم المستخدم مستخدم مسبقا');
    throw e;
  }
  return sendJson(res, 200, { ok: true });
}
async function resetPassword(req, res, id) {
  const body = await readJson(req);
  const password = String(body.password || '');
  if (password.length < 6) throw httpError(400, 'كلمة المرور 6 أحرف على الأقل');
  const info = db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hashPassword(password), id);
  if (!info.changes) throw httpError(404, 'المستخدم غير موجود');
  for (const [sid, s] of sessions) if (s.userId === id) sessions.delete(sid);
  return sendJson(res, 200, { ok: true });
}
function deleteUser(res, id, sess) {
  if (id === sess.userId) throw httpError(400, 'لا يمكنك حذف حسابك الحالي');
  const u = db.prepare('SELECT role FROM users WHERE id=?').get(id);
  if (!u) throw httpError(404, 'المستخدم غير موجود');
  if (u.role === 'admin') {
    const c = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role='admin'").get().c;
    if (c <= 1) throw httpError(400, 'لا يمكن حذف آخر حساب مالك');
  }
  db.prepare('DELETE FROM users WHERE id=?').run(id);
  for (const [sid, s] of sessions) if (s.userId === id) sessions.delete(sid);
  return sendJson(res, 200, { ok: true });
}

async function changeOwnPassword(req, res, sess) {
  const body = await readJson(req);
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(sess.userId);
  if (!user) throw httpError(404, 'المستخدم غير موجود');
  if (!verifyPassword(String(body.current || ''), user.password_hash)) throw httpError(400, 'كلمة المرور الحالية غير صحيحة');
  const np = String(body.password || '');
  if (np.length < 6) throw httpError(400, 'كلمة المرور الجديدة 6 أحرف على الأقل');
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hashPassword(np), user.id);
  return sendJson(res, 200, { ok: true });
}

async function login(req, res) {
  const ip = req.socket.remoteAddress || 'unknown';
  const f = fails.get(ip);
  if (f && f.lockUntil > Date.now()) throw httpError(429, 'محاولات فاشلة كثيرة. حاول بعد 15 دقيقة');
  const body = await readJson(req);
  const username = String(body.username || '').trim();
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  const passOk = user ? verifyPassword(String(body.password || ''), user.password_hash) : false;
  const roleOk = !body.owner || (user && user.role === 'admin');
  if (!user || !passOk || !roleOk) {
    const cur = fails.get(ip) || { count: 0, lockUntil: 0 };
    cur.count++;
    if (cur.count >= MAX_FAILS) { cur.lockUntil = Date.now() + LOCK_MS; cur.count = 0; }
    fails.set(ip, cur);
    throw httpError(401, 'اسم المستخدم أو كلمة المرور غير صحيحة');
  }
  fails.delete(ip);
  const cookie = createSession(user);
  return sendJson(res, 200, { role: user.role, displayName: user.display_name }, { 'Set-Cookie': cookie });
}

async function admin(req, res, url, sess, m, p) {
  if (m === 'POST' && p === '/api/admin/upload') return handleUpload(req, res, url, sess);
  if (m === 'GET' && p === '/api/admin/uploads') {
    return sendJson(res, 200, { uploads: db.prepare(`
      SELECT id, filename, record_date AS recordDate, rows_count AS rows, total, uploaded_at AS uploadedAt
      FROM uploads ORDER BY record_date DESC, id DESC`).all() });
  }
  let mt;
  if (m === 'DELETE' && (mt = p.match(/^\/api\/admin\/uploads\/(\d+)$/))) {
    const info = db.prepare('DELETE FROM uploads WHERE id=?').run(Number(mt[1]));
    if (!info.changes) throw httpError(404, 'الملف غير موجود');
    return sendJson(res, 200, { ok: true });
  }
  if (m === 'GET' && p === '/api/admin/users') return sendJson(res, 200, { users: listUsers() });
  if (m === 'POST' && p === '/api/admin/users') return createUser(req, res);
  if (m === 'POST' && (mt = p.match(/^\/api\/admin\/users\/(\d+)\/password$/))) return resetPassword(req, res, Number(mt[1]));
  if (m === 'DELETE' && (mt = p.match(/^\/api\/admin\/users\/(\d+)$/))) return deleteUser(res, Number(mt[1]), sess);
  return sendJson(res, 404, { error: 'not found' });
}

async function api(req, res, url) {
  const p = url.pathname, m = req.method;
  try {
    if (m === 'POST' && p === '/api/login') return await login(req, res);
    if (m === 'POST' && p === '/api/logout') {
      const sid = parseCookies(req).sid;
      if (sid) sessions.delete(sid);
      return sendJson(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict' });
    }
    const sess = getSession(req);
    if (!sess) return sendJson(res, 401, { error: 'انتهت الجلسة، يرجى تسجيل الدخول' });
    let mt;
    if (m === 'GET' && p === '/api/me') return sendJson(res, 200, { username: sess.username, displayName: sess.display, role: sess.role });
    if (m === 'GET' && p === '/api/summary') return sendJson(res, 200, summary(url));
    if (m === 'GET' && (mt = p.match(/^\/api\/employees\/(\d+)$/))) return sendJson(res, 200, employeeDetail(url, Number(mt[1])));
    if (m === 'POST' && p === '/api/account/password') return await changeOwnPassword(req, res, sess);
    if (p.startsWith('/api/admin/')) {
      if (sess.role !== 'admin') return sendJson(res, 403, { error: 'صلاحية غير كافية' });
      return await admin(req, res, url, sess, m, p);
    }
    return sendJson(res, 404, { error: 'not found' });
  } catch (err) {
    if (!err.status) console.error(err);
    return sendJson(res, err.status || 500, { error: err.status ? err.message : 'حدث خطأ في الخادم', ...(err.extra || {}) });
  }
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  if (p.startsWith('/api/')) return await api(req, res, url);
  if (req.method !== 'GET') return sendJson(res, 405, { error: 'method not allowed' });
  if (p === '/') return sendFile(res, 'login.html');
  if (p === '/dashboard') return getSession(req) ? sendFile(res, 'dashboard.html') : redirect(res, '/');
  if (p === '/owner-console') return sendFile(res, 'owner.html');
  if (['/common.js', '/style.css', '/vendor/chart.js'].includes(p)) return sendFile(res, p.slice(1));
  return sendJson(res, 404, { error: 'not found' });
}

http.createServer((req, res) => {
  handle(req, res).catch(err => {
    console.error(err);
    if (!res.headersSent) sendJson(res, 500, { error: 'خطأ في الخادم' });
  });
}).listen(PORT, HOST, () => console.log(`Server running on http://0.0.0.0:${PORT}`));
