const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const PORT = process.env.PORT || 3000;
const db = new Database(path.join(__dirname, 'data.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, hash TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER, created INTEGER);
CREATE TABLE IF NOT EXISTS keys(id INTEGER PRIMARY KEY, user_id INTEGER, value TEXT, used INTEGER DEFAULT 0, picked_at INTEGER, batch TEXT, UNIQUE(user_id, value));
`);

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  const s = db.prepare('SELECT user_id FROM sessions WHERE token=?').get(t);
  if (!s) return res.status(401).json({ error: 'Chưa đăng nhập' });
  req.uid = s.user_id; next();
}
const newSession = uid => {
  const t = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(t, uid, Date.now());
  return t;
};

app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || username.length < 3 || !password || password.length < 6)
    return res.status(400).json({ error: 'Tên ≥ 3 ký tự, mật khẩu ≥ 6 ký tự' });
  try {
    const r = db.prepare('INSERT INTO users(username,hash) VALUES(?,?)').run(username.trim(), bcrypt.hashSync(password, 10));
    res.json({ token: newSession(r.lastInsertRowid), username });
  } catch { res.status(400).json({ error: 'Tên đăng nhập đã tồn tại' }); }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username=?').get((username || '').trim());
  if (!u || !bcrypt.compareSync(password || '', u.hash))
    return res.status(401).json({ error: 'Sai tên đăng nhập hoặc mật khẩu' });
  res.json({ token: newSession(u.id), username: u.username });
});

app.get('/api/state', auth, (req, res) => {
  const q = s => db.prepare(s).all(req.uid);
  const remaining = q('SELECT value FROM keys WHERE user_id=? AND used=0 ORDER BY id').map(r => r.value);
  const history = q('SELECT value, picked_at, batch FROM keys WHERE user_id=? AND used=1 ORDER BY picked_at DESC LIMIT 500');
  const batches = db.prepare('SELECT COUNT(DISTINCT batch) n FROM keys WHERE user_id=? AND used=1').get(req.uid).n;
  res.json({ remaining, history, batches, total: remaining.length + history.length });
});

app.post('/api/keys', auth, (req, res) => {
  const lines = [...new Set(String(req.body.text || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean))];
  const ins = db.prepare('INSERT OR IGNORE INTO keys(user_id,value) VALUES(?,?)');
  let added = 0;
  db.transaction(() => lines.forEach(k => { added += ins.run(req.uid, k).changes; }))();
  res.json({ added, skipped: lines.length - added });
});

app.post('/api/pick', auth, (req, res) => {
  const n = Math.max(1, Math.min(1000, parseInt(req.body.count) || 1));
  const out = db.transaction(() => {
    const rows = db.prepare('SELECT id,value FROM keys WHERE user_id=? AND used=0 ORDER BY RANDOM() LIMIT ?').all(req.uid, n);
    const batch = crypto.randomBytes(6).toString('hex'), now = Date.now();
    const up = db.prepare('UPDATE keys SET used=1, picked_at=?, batch=? WHERE id=?');
    rows.forEach(r => up.run(now, batch, r.id));
    return rows.map(r => r.value);
  })();
  if (!out.length) return res.status(400).json({ error: 'Kho key đang trống' });
  res.json({ keys: out });
});

app.delete('/api/keys', auth, (req, res) => {
  db.prepare('DELETE FROM keys WHERE user_id=? AND used=0').run(req.uid);
  res.json({ ok: true });
});

app.listen(PORT, '127.0.0.1', () => console.log('Running on http://127.0.0.1:' + PORT));
