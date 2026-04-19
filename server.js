'use strict';
const express      = require('express');
const http         = require('http');
const { PeerServer } = require('peer');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const { randomUUID: uuid } = require('crypto');
const fs           = require('fs');
const path         = require('path');

const PORT    = process.env.PORT || 3000;
const SECRET  = process.env.JWT_SECRET || 'nexlink-dev-secret-change-in-production';
const DB_PATH = path.join(__dirname, 'data', 'users.json');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); }
  catch { return { users: [] }; }
}
function saveDB(db) { fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); }
function findUser(email) { return loadDB().users.find(u => u.email.toLowerCase() === email.toLowerCase()); }
function sanitize(u) { const { password, ...safe } = u; return safe; }

const app = express();
app.use(express.json({ limit: '5mb' })); // allow base64 avatars
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const peerServer = PeerServer({ server, path: '/peerjs', allow_discovery: true });
peerServer.on('connection', c => console.log(`[peer] +${c.getId()}`));
peerServer.on('disconnect', c => console.log(`[peer] -${c.getId()}`));

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
}

// ── REGISTER ──────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { email, password, displayName, username, color, status } = req.body;
  if (!email || !password || !displayName || !username)
    return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const db = loadDB();
  if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(400).json({ error: 'Email already registered' });
  if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(400).json({ error: 'Username already taken' });

  const user = {
    id: uuid(), email: email.toLowerCase(),
    password: await bcrypt.hash(password, 10),
    displayName, username: username.toLowerCase(),
    color: color || '#3b82f6', status: status || 'Available',
    avatar: null, contacts: [], createdAt: Date.now()
  };
  db.users.push(user); saveDB(db);
  const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '30d' });
  res.json({ token, user: sanitize(user) });
});

// ── LOGIN ─────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = findUser(email);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Invalid email or password' });
  const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '30d' });
  res.json({ token, user: sanitize(user) });
});

// ── ME ────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  const user = loadDB().users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json(sanitize(user));
});

app.patch('/api/me', requireAuth, async (req, res) => {
  const db = loadDB();
  const idx = db.users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  ['displayName','color','status','username','avatar'].forEach(k => {
    if (req.body[k] !== undefined) db.users[idx][k] = req.body[k];
  });
  if (req.body.newPassword) {
    if (!req.body.currentPassword) return res.status(400).json({ error: 'Current password required' });
    if (!(await bcrypt.compare(req.body.currentPassword, db.users[idx].password)))
      return res.status(400).json({ error: 'Current password is incorrect' });
    db.users[idx].password = await bcrypt.hash(req.body.newPassword, 10);
  }
  saveDB(db);
  res.json(sanitize(db.users[idx]));
});

// ── CONTACTS ─────────────────────────────────────────
app.get('/api/contacts', requireAuth, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const contacts = (user.contacts || []).map(c => {
    const found = db.users.find(u => u.username === c.username);
    return found ? { ...c, displayName: found.displayName, color: found.color, status: found.status, avatar: found.avatar } : c;
  });
  res.json(contacts);
});

app.post('/api/contacts', requireAuth, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });
  const db = loadDB();
  const me = db.users.find(u => u.id === req.user.id);
  const target = db.users.find(u => u.username === username.toLowerCase());
  if (!target) return res.status(404).json({ error: 'No user found with that username' });
  if (target.id === req.user.id) return res.status(400).json({ error: "You can't add yourself" });
  if ((me.contacts || []).find(c => c.username === target.username))
    return res.status(400).json({ error: 'Already in contacts' });
  me.contacts = me.contacts || [];
  me.contacts.push({ username: target.username, displayName: target.displayName, color: target.color, addedAt: Date.now() });
  saveDB(db);
  res.json({ username: target.username, displayName: target.displayName, color: target.color, avatar: target.avatar });
});

app.delete('/api/contacts/:username', requireAuth, (req, res) => {
  const db = loadDB();
  const me = db.users.find(u => u.id === req.user.id);
  me.contacts = (me.contacts || []).filter(c => c.username !== req.params.username);
  saveDB(db); res.json({ ok: true });
});

app.get('/api/user/:username', requireAuth, (req, res) => {
  const user = loadDB().users.find(u => u.username === req.params.username.toLowerCase());
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(sanitize(user));
});

// ── RECENTS ───────────────────────────────────────────
app.get('/api/recents', requireAuth, (req, res) => {
  const user = loadDB().users.find(u => u.id === req.user.id);
  res.json(user?.recents || []);
});
app.post('/api/recents', requireAuth, (req, res) => {
  const db = loadDB();
  const idx = db.users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.users[idx].recents = [{ ...req.body, ts: Date.now() }, ...(db.users[idx].recents || [])].slice(0, 50);
  saveDB(db); res.json({ ok: true });
});
app.post('/api/recents/clear', requireAuth, (req, res) => {
  const db = loadDB();
  const idx = db.users.findIndex(u => u.id === req.user.id);
  if (idx !== -1) { db.users[idx].recents = []; saveDB(db); }
  res.json({ ok: true });
});

// ── START — bind 0.0.0.0 so Railway can reach it ─────
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  NexLink running on port ${PORT}\n`);
});