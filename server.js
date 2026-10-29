const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'lucien.json');
const SESSION_COOKIE = 'lucien_session';
const sessions = new Map();
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;

app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

let db = { users: [], chats: [], memories: [] };
let writeQueue = Promise.resolve();
async function loadDb() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    const parsed = JSON.parse(await fs.readFile(DB_FILE, 'utf8'));
    db = {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      chats: Array.isArray(parsed.chats) ? parsed.chats : [],
      memories: Array.isArray(parsed.memories) ? parsed.memories : []
    };
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    await saveDb();
  }
}
function saveDb() {
  writeQueue = writeQueue.then(async () => {
    const temp = DB_FILE + '.tmp';
    await fs.writeFile(temp, JSON.stringify(db), { mode: 0o600 });
    await fs.rename(temp, DB_FILE);
  });
  return writeQueue;
}
function id() { return crypto.randomUUID(); }
function cookieOptions() {
  return { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/' };
}
function currentUser(req) {
  const token = req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith(SESSION_COOKIE + '='))?.slice(SESSION_COOKIE.length + 1);
  if (!token) return null;
  const session = sessions.get(decodeURIComponent(token));
  if (!session || session.expires < Date.now()) {
    sessions.delete(decodeURIComponent(token));
    return null;
  }
  session.expires = Date.now() + SESSION_TTL;
  return db.users.find(u => u.id === session.userId) || null;
}
function publicUser(user) { return { id: user.id, username: user.username }; }
function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'Please sign in again.' });
  req.user = user;
  next();
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function checkPassword(password, user) {
  const actual = crypto.scryptSync(password, user.salt, 64);
  const expected = Buffer.from(user.passwordHash, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
function setSession(res, user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { userId: user.id, expires: Date.now() + SESSION_TTL });
  res.cookie(SESSION_COOKIE, token, { ...cookieOptions(), maxAge: SESSION_TTL });
}
function cleanMessages(messages) {
  if (!Array.isArray(messages)) return [];
  return messages.slice(-40).filter(m => m && ['user', 'assistant'].includes(m.role) && typeof m.content === 'string')
    .map(m => ({ role: m.role, content: m.content.slice(0, 12000) }));
}

app.get('/api/auth/me', (req, res) => {
  const user = currentUser(req);
  res.json({ user: user ? publicUser(user) : null });
});
app.post('/api/auth/signup', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!/^[a-zA-Z0-9_-]{3,24}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–24 letters, numbers, underscores, or hyphens.' });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Password must be 8–128 characters.' });
  if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'That username is already taken.' });
  const pw = hashPassword(password);
  const user = { id: id(), username, salt: pw.salt, passwordHash: pw.hash, createdAt: new Date().toISOString() };
  db.users.push(user);
  await saveDb();
  setSession(res, user);
  res.status(201).json({ user: publicUser(user) });
});
app.post('/api/auth/login', (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user || !checkPassword(password, user)) return res.status(401).json({ error: 'Incorrect username or password.' });
  setSession(res, user);
  res.json({ user: publicUser(user) });
});
app.post('/api/auth/logout', (req, res) => {
  const token = req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith(SESSION_COOKIE + '='))?.slice(SESSION_COOKIE.length + 1);
  if (token) sessions.delete(decodeURIComponent(token));
  res.clearCookie(SESSION_COOKIE, cookieOptions());
  res.json({ ok: true });
});

app.get('/api/chats', requireAuth, (req, res) => {
  const chats = db.chats.filter(c => c.userId === req.user.id).sort((a,b) => b.updatedAt.localeCompare(a.updatedAt))
    .map(({ id, title, messages, createdAt, updatedAt }) => ({ id, title, messages, createdAt, updatedAt }));
  res.json({ chats });
});
app.post('/api/chats', requireAuth, async (req, res) => {
  const messages = cleanMessages(req.body?.messages);
  const title = String(req.body?.title || 'New chat').slice(0, 100);
  if (!messages.length) return res.status(400).json({ error: 'A chat needs at least one message.' });
  const now = new Date().toISOString();
  const chat = { id: id(), userId: req.user.id, title, messages, createdAt: now, updatedAt: now };
  db.chats.push(chat);
  await saveDb();
  res.status(201).json({ chat: { id: chat.id, title: chat.title, messages: chat.messages, createdAt: now, updatedAt: now } });
});
app.put('/api/chats/:id', requireAuth, async (req, res) => {
  const chat = db.chats.find(c => c.id === req.params.id && c.userId === req.user.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found.' });
  const messages = cleanMessages(req.body?.messages);
  if (!messages.length) return res.status(400).json({ error: 'A chat needs at least one message.' });
  chat.title = String(req.body?.title || chat.title).slice(0, 100);
  chat.messages = messages;
  chat.updatedAt = new Date().toISOString();
  await saveDb();
  res.json({ chat: { id: chat.id, title: chat.title, messages: chat.messages, updatedAt: chat.updatedAt } });
});
app.delete('/api/chats/:id', requireAuth, async (req, res) => {
  const before = db.chats.length;
  db.chats = db.chats.filter(c => !(c.id === req.params.id && c.userId === req.user.id));
  if (before === db.chats.length) return res.status(404).json({ error: 'Chat not found.' });
  await saveDb();
  res.json({ ok: true });
});

app.get('/api/memory', requireAuth, (req, res) => {
  res.json({ memories: db.memories.filter(m => m.userId === req.user.id).sort((a,b) => b.createdAt.localeCompare(a.createdAt)) });
});
app.post('/api/memory', requireAuth, async (req, res) => {
  const content = String(req.body?.content || '').trim();
  if (!content || content.length > 1000) return res.status(400).json({ error: 'Memory must be between 1 and 1000 characters.' });
  const memory = { id: id(), userId: req.user.id, content, source: 'manual', createdAt: new Date().toISOString() };
  db.memories.push(memory);
  await saveDb();
  res.status(201).json({ memory });
});
app.delete('/api/memory', requireAuth, async (req, res) => {
  db.memories = db.memories.filter(m => m.userId !== req.user.id);
  await saveDb();
  res.json({ ok: true });
});
app.delete('/api/memory/:id', requireAuth, async (req, res) => {
  const before = db.memories.length;
  db.memories = db.memories.filter(m => !(m.id === req.params.id && m.userId === req.user.id));
  if (before === db.memories.length) return res.status(404).json({ error: 'Memory not found.' });
  await saveDb();
  res.json({ ok: true });
});

const models = [
  { id: 'google:gemini-3.8-flash', name: 'Gemini 3.8 Flash · Google' },
  { id: 'openapis:claude-opus-4-7', name: 'Claude Opus 4.7 · OpenAPIs beta' },
  { id: 'openapis:gpt-5.4', name: 'GPT-5.4 · OpenAPIs beta' }
];
app.get('/api/models', (req, res) => res.json({ models, openrouterEnabled: false, provider: 'Google Gemini + OpenAPIs beta' }));

app.post('/api/chat', requireAuth, async (req, res) => {
  const messages = cleanMessages(req.body?.messages);
  if (!messages.length || messages[messages.length - 1].role !== 'user') return res.status(400).json({ error: 'Send a message to start.' });

  const requested = String(req.body?.model || '');
  const map = {
    'openapis:claude-opus-4-7': 'claude-opus-4-7',
    'openapis:gpt-5.4': 'gpt-5.4'
  };

  try {
    if (!requested || requested === 'google:gemini-3.8-flash') {
      const key = process.env.GEMINI_API_KEY;
      if (!key) return res.status(503).json({ error: 'Gemini is not configured yet. Add GEMINI_API_KEY in Railway Variables.' });

      const contents = messages.map(m => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }]
      }));
      const response = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent', {
        method: 'POST',
        headers: { 'x-goog-api-key': key, 'content-type': 'application/json' },
        body: JSON.stringify({ contents, generationConfig: { maxOutputTokens: 1200 } })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = data?.error?.message || 'Google Gemini rejected the request.';
        return res.status(502).json({ error: 'Gemini API error (' + response.status + '): ' + String(detail).slice(0, 240) });
      }
      const reply = (data.candidates?.[0]?.content?.parts || []).filter(p => typeof p.text === 'string').map(p => p.text).join('\n');
      if (!reply) return res.status(502).json({ error: 'Gemini returned an empty reply. Check the model response or safety settings.' });
      return res.json({ reply, model: 'gemini-3.8-flash' });
    }

    const model = map[requested];
    if (!model) return res.status(400).json({ error: 'Unknown model selected.' });
    const base = process.env.OPENAPIS_BASE_URL || 'https://api.openapis.online';
    const key = process.env.OPENAPIS_API_KEY || 'admin';
    const isClaude = model.startsWith('claude-');
    const url = isClaude ? base.replace(/\/$/, '') + '/anthropic/v1/messages' : base.replace(/\/$/, '') + '/openai/v1/chat/completions';
    const response = await fetch(url, {
      method: 'POST',
      headers: isClaude
        ? { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }
        : { 'Authorization': 'Bearer ' + key, 'content-type': 'application/json' },
      body: JSON.stringify({ model, max_tokens: 1200, messages })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = data?.error?.message || data?.error || data?.message || 'Provider rejected the request.';
      return res.status(502).json({ error: 'AI provider error (' + response.status + '): ' + String(detail).slice(0, 240) });
    }
    const reply = isClaude
      ? (Array.isArray(data.content) ? data.content.filter(x => x.type === 'text').map(x => x.text).join('\n') : '')
      : (data.choices?.[0]?.message?.content || '');
    if (!reply) return res.status(502).json({ error: 'The AI provider returned an empty reply.' });
    res.json({ reply, model });
  } catch (e) {
    res.status(502).json({ error: 'Could not reach the AI provider. Please try again shortly.' });
  }
});

app.use(express.static(__dirname, { extensions: ['html'] }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
loadDb().then(() => app.listen(PORT, '0.0.0.0', () => console.log('Lucien 3.0 listening on port ' + PORT)))
  .catch(err => { console.error('Failed to load database:', err); process.exit(1); });
