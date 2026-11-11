async function api(path, opts = {}) {
  const init = { method: opts.method || 'GET', credentials: 'same-origin', headers: {} };
  if (opts.raw !== undefined) { init.body = opts.raw; Object.assign(init.headers, opts.headers || {}); }
  else if (opts.body !== undefined) { init.body = JSON.stringify(opts.body); init.headers['Content-Type'] = 'application/json'; }
  const r = await fetch(path, init);
  let data = {};
  try { data = await r.json(); } catch {}
  if (!r.ok) { const err = new Error(data.error || 'حدث خطأ'); err.status = r.status; Object.assign(err, data); throw err; }
  return data;
}
function fmt(n) { return Number(n || 0).toLocaleString('en-US', { maximumFractionDigits: 2 }); }
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function todayRiyadh() { return new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Riyadh' }); }
async function logout() { try { await api('/api/logout', { method: 'POST' }); } catch {} location.href = '/'; }
