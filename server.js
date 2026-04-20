'use strict';
const express  = require('express');
const http     = require('http');
const { WebSocketServer } = require('ws');
const { PeerServer } = require('peer');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { randomUUID: uuid } = require('crypto');
const fs       = require('fs');
const path     = require('path');

const PORT    = process.env.PORT || 3000;
const SECRET  = process.env.JWT_SECRET || 'nexlink-dev-secret-change-in-production';
const DB_PATH = path.join(__dirname, 'data', 'users.json');

// ── DATA DIR + FRESH DB ───────────────────────────────
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// Always start fresh — wipe any existing user data on deploy
saveDB({ users: [] });

function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); }
  catch { return { users: [] }; }
}
function saveDB(db) { fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); }
function findUser(email) { return loadDB().users.find(u => u.email.toLowerCase() === email.toLowerCase()); }
function sanitize(u) { const { password, ...safe } = u; return safe; }

// ── PASSWORD STRENGTH ─────────────────────────────────
function strongPassword(pw) {
  return pw.length >= 8 &&
    /[A-Z]/.test(pw) &&
    /[0-9]/.test(pw) &&
    /[^A-Za-z0-9]/.test(pw);
}

// ── EXPRESS + SERVERS ─────────────────────────────────
const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);

// PeerJS for WebRTC signalling
const peerServer = PeerServer({ server, path: '/peerjs', allow_discovery: true });
peerServer.on('connection', c => console.log(`[peer] +${c.getId()}`));
peerServer.on('disconnect', c => console.log(`[peer] -${c.getId()}`));

// WebSocket for real-time DMs and contact notifications
const wss = new WebSocketServer({ server, path: '/ws' });
const onlineUsers = new Map(); // username -> ws

wss.on('connection', (ws, req) => {
  let username = null;

  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'auth') {
      try {
        const payload = jwt.verify(msg.token, SECRET);
        const db = loadDB();
        const user = db.users.find(u => u.id === payload.id);
        if (!user) { ws.close(); return; }
        username = user.username;
        onlineUsers.set(username, ws);
        ws.send(JSON.stringify({ type: 'authed', username }));
        console.log(`[ws] ${username} connected`);
      } catch { ws.close(); }
      return;
    }

    if (!username) return;

    if (msg.type === 'dm') {
      const { to, text, ts, id: msgId } = msg;
      if (!to || !text) return;

      // Persist to both users' inboxes
      const db = loadDB();
      const meIdx = db.users.findIndex(u => u.username === username);
      const theirIdx = db.users.findIndex(u => u.username === to);
      if (meIdx === -1 || theirIdx === -1) return;

      const entry = { id: msgId || uuid(), from: username, to, text, ts: ts || Date.now() };
      db.users[meIdx].messages = db.users[meIdx].messages || [];
      db.users[theirIdx].messages = db.users[theirIdx].messages || [];
      db.users[meIdx].messages.push(entry);
      db.users[theirIdx].messages.push(entry);
      // Keep last 500 messages per user
      db.users[meIdx].messages = db.users[meIdx].messages.slice(-500);
      db.users[theirIdx].messages = db.users[theirIdx].messages.slice(-500);
      saveDB(db);

      // Deliver to recipient if online
      const recipientWs = onlineUsers.get(to);
      if (recipientWs && recipientWs.readyState === 1) {
        recipientWs.send(JSON.stringify({ type: 'dm', ...entry }));
      }
      // Echo back to sender
      ws.send(JSON.stringify({ type: 'dm-sent', ...entry }));
    }

    if (msg.type === 'contact-request') {
      const { to } = msg;
      const db = loadDB();
      const meIdx = db.users.findIndex(u => u.username === username);
      const theirIdx = db.users.findIndex(u => u.username === to);
      if (meIdx === -1 || theirIdx === -1) return;

      // Notify recipient if online
      const recipientWs = onlineUsers.get(to);
      if (recipientWs && recipientWs.readyState === 1) {
        recipientWs.send(JSON.stringify({
          type: 'contact-request',
          from: username,
          displayName: db.users[meIdx].displayName,
          avatar: db.users[meIdx].avatar,
          color: db.users[meIdx].color
        }));
      }
    }
  });

  ws.on('close', () => {
    if (username) { onlineUsers.delete(username); console.log(`[ws] ${username} disconnected`); }
  });

  ws.on('error', () => {});
});

// ── AUTH MIDDLEWARE ───────────────────────────────────
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

  if (!strongPassword(password))
    return res.status(400).json({ error: 'Password must be at least 8 characters and include an uppercase letter, a number, and a special character' });

  const db = loadDB();
  if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(400).json({ error: 'Email already registered' });
  if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(400).json({ error: 'Username already taken — please choose another' });

  const user = {
    id: uuid(), email: email.toLowerCase(),
    password: await bcrypt.hash(password, 10),
    displayName, username: username.toLowerCase(),
    color: color || '#3b82f6', status: status || 'Available',
    avatar: null, contacts: [], contactRequests: [], messages: [],
    recents: [], createdAt: Date.now()
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

  // Username uniqueness check on update
  if (req.body.username) {
    const taken = db.users.find(u => u.username === req.body.username.toLowerCase() && u.id !== req.user.id);
    if (taken) return res.status(400).json({ error: 'Username already taken' });
  }

  ['displayName','color','status','username','avatar'].forEach(k => {
    if (req.body[k] !== undefined) db.users[idx][k] = req.body[k];
  });
  if (req.body.newPassword) {
    if (!req.body.currentPassword) return res.status(400).json({ error: 'Current password required' });
    if (!(await bcrypt.compare(req.body.currentPassword, db.users[idx].password)))
      return res.status(400).json({ error: 'Current password is incorrect' });
    if (!strongPassword(req.body.newPassword))
      return res.status(400).json({ error: 'New password must be at least 8 characters with an uppercase letter, number, and special character' });
    db.users[idx].password = await bcrypt.hash(req.body.newPassword, 10);
  }
  saveDB(db);
  res.json(sanitize(db.users[idx]));
});

// ── USER LOOKUP ───────────────────────────────────────
app.get('/api/user/:username', requireAuth, (req, res) => {
  const user = loadDB().users.find(u => u.username === req.params.username.toLowerCase());
  if (!user) return res.status(404).json({ error: 'User not found' });
  // Return only public info
  res.json({ username: user.username, displayName: user.displayName, color: user.color, avatar: user.avatar, status: user.status });
});

// ── CONTACT REQUESTS ──────────────────────────────────
app.get('/api/contact-requests', requireAuth, (req, res) => {
  const user = loadDB().users.find(u => u.id === req.user.id);
  res.json(user?.contactRequests || []);
});

app.post('/api/contact-requests', requireAuth, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });

  const db = loadDB();
  const me = db.users.find(u => u.id === req.user.id);
  const target = db.users.find(u => u.username === username.toLowerCase());

  if (!target) return res.status(404).json({ error: 'No user found with that username' });
  if (target.id === req.user.id) return res.status(400).json({ error: "You can't add yourself" });
  if ((me.contacts || []).find(c => c.username === target.username))
    return res.status(400).json({ error: 'Already in your contacts' });

  // Check for duplicate pending request
  target.contactRequests = target.contactRequests || [];
  if (target.contactRequests.find(r => r.from === me.username && r.status === 'pending'))
    return res.status(400).json({ error: 'Request already sent' });

  const requestId = uuid();
  target.contactRequests.push({
    id: requestId, from: me.username,
    displayName: me.displayName, avatar: me.avatar, color: me.color,
    ts: Date.now(), status: 'pending'
  });
  saveDB(db);

  // Notify recipient via WS if online
  const recipientWs = onlineUsers.get(target.username);
  if (recipientWs && recipientWs.readyState === 1) {
    recipientWs.send(JSON.stringify({
      type: 'contact-request',
      id: requestId, from: me.username,
      displayName: me.displayName, avatar: me.avatar, color: me.color
    }));
  }

  res.json({ ok: true, id: requestId });
});

app.post('/api/contact-requests/:id/accept', requireAuth, (req, res) => {
  const db = loadDB();
  const meIdx = db.users.findIndex(u => u.id === req.user.id);
  if (meIdx === -1) return res.status(404).json({ error: 'Not found' });

  const reqEntry = (db.users[meIdx].contactRequests || []).find(r => r.id === req.params.id);
  if (!reqEntry) return res.status(404).json({ error: 'Request not found' });

  const senderIdx = db.users.findIndex(u => u.username === reqEntry.from);
  if (senderIdx === -1) return res.status(404).json({ error: 'Sender not found' });

  // Add each to the other's contacts
  const me = db.users[meIdx];
  const sender = db.users[senderIdx];

  me.contacts = me.contacts || [];
  sender.contacts = sender.contacts || [];

  if (!me.contacts.find(c => c.username === sender.username))
    me.contacts.push({ username: sender.username, displayName: sender.displayName, color: sender.color, avatar: sender.avatar, addedAt: Date.now() });
  if (!sender.contacts.find(c => c.username === me.username))
    sender.contacts.push({ username: me.username, displayName: me.displayName, color: me.color, avatar: me.avatar, addedAt: Date.now() });

  // Remove the request
  db.users[meIdx].contactRequests = db.users[meIdx].contactRequests.filter(r => r.id !== req.params.id);
  saveDB(db);

  // Notify sender via WS
  const senderWs = onlineUsers.get(sender.username);
  if (senderWs && senderWs.readyState === 1) {
    senderWs.send(JSON.stringify({
      type: 'contact-accepted',
      username: me.username, displayName: me.displayName, color: me.color, avatar: me.avatar
    }));
  }

  res.json({ ok: true });
});

app.post('/api/contact-requests/:id/decline', requireAuth, (req, res) => {
  const db = loadDB();
  const idx = db.users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.users[idx].contactRequests = (db.users[idx].contactRequests || []).filter(r => r.id !== req.params.id);
  saveDB(db);
  res.json({ ok: true });
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

app.delete('/api/contacts/:username', requireAuth, (req, res) => {
  const db = loadDB();
  const me = db.users.find(u => u.id === req.user.id);
  me.contacts = (me.contacts || []).filter(c => c.username !== req.params.username);
  saveDB(db); res.json({ ok: true });
});

// ── DIRECT MESSAGES ───────────────────────────────────
app.get('/api/messages/:username', requireAuth, (req, res) => {
  const db = loadDB();
  const me = db.users.find(u => u.id === req.user.id);
  if (!me) return res.status(404).json({ error: 'Not found' });
  const other = req.params.username;
  const msgs = (me.messages || []).filter(m =>
    (m.from === me.username && m.to === other) ||
    (m.from === other && m.to === me.username)
  );
  res.json(msgs.slice(-100));
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

// ── START ─────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  console.log(`NexLink running on port ${PORT}`);
});
