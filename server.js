// ============================================================
// سيرفر POV — Express + web-push
// بيوفر 3 حاجات:
//   1) تسجيل دخول/حساب بسيط (/auth/register, /auth/login)
//   2) مزامنة بيانات التطبيق بين الأجهزة (/snapshot, /sync, /account/data)
//   3) إشعارات Push حقيقية توصل حتى لو التطبيق مقفول تمامًا
//      (/push/vapid-public-key, /push/subscribe, /push/queue)
// التخزين هنا ملفات JSON بسيطة — يكفي لاستخدام شخصي/صغير.
// لو الاستخدام كبر، ابدّل الجزء بتاع db.js بقاعدة بيانات حقيقية
// (Postgres/Mongo) من غير ما تغيّر شكل الـ endpoints.
// ============================================================
console.log('=== POV SERVER STARTING ===');
console.log('Node:', process.version);
console.log('PORT:', process.env.PORT);
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const webpush = require('web-push');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_CONTACT = process.env.VAPID_CONTACT || 'mailto:admin@example.com';

if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  console.warn('[تحذير] VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY مش متظبطين — إشعارات الـ Push هتفشل.');
  console.warn('شغّل: npm run generate-vapid وحط الناتج في متغيرات البيئة.');
} else {
  webpush.setVapidDetails(VAPID_CONTACT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
}

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------------- تخزين بسيط على ملفات JSON ----------------
function filePath(name) { return path.join(DATA_DIR, name + '.json'); }
function readJSON(name, fallback) {
  try { return JSON.parse(fs.readFileSync(filePath(name), 'utf8')); }
  catch (e) { return fallback; }
}
function writeJSON(name, data) {
  const tmp = filePath(name) + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data));
  fs.renameSync(tmp, filePath(name));
}
// بنيّة البيانات:
// users:        { [userId]: { email, salt, hash, createdAt } }
// tokens:       { [token]: userId }
// snapshots:    { [userId]: { [key]: {v, u} } }
// subscriptions:{ [userId]: [ pushSubscriptionObject, ... ] }
// queue:        { [userId]: [ {id, time /*ISO*/, title, body, tag}, ... ] }
let users = readJSON('users', {});
let tokens = readJSON('tokens', {});
let snapshots = readJSON('snapshots', {});
let subscriptions = readJSON('subscriptions', {});
let queue = readJSON('queue', {});
function persistUsers() { writeJSON('users', users); writeJSON('tokens', tokens); }
function persistSnapshots() { writeJSON('snapshots', snapshots); }
function persistSubs() { writeJSON('subscriptions', subscriptions); }
function persistQueue() { writeJSON('queue', queue); }

// ---------------- تشفير كلمة السر (scrypt مدمجة في Node، من غير أي مكتبة خارجية) ----------------
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(check), Buffer.from(hash));
}
function newToken() { return crypto.randomBytes(32).toString('hex'); }

// ---------------- Express ----------------
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  const userId = token && tokens[token];
  if (!userId || !users[userId]) return res.status(401).json({ error: 'الجلسة غير صالحة، سجّل دخول تاني' });
  req.userId = userId;
  next();
}

app.get('/', (req, res) => res.json({ ok: true, service: 'pov-server' }));

// ---------- تسجيل / دخول ----------
app.post('/auth/register', (req, res) => {
  const email = String((req.body && req.body.email) || '').trim().toLowerCase();
  const password = String((req.body && req.body.password) || '');
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'بريد إلكتروني غير صحيح' });
  if (password.length < 8) return res.status(400).json({ error: 'كلمة المرور لازم ٨ حروف على الأقل' });
  const exists = Object.values(users).some(u => u.email === email);
  if (exists) return res.status(409).json({ error: 'الإيميل ده متسجل قبل كده' });
  const userId = crypto.randomBytes(12).toString('hex');
  const { salt, hash } = hashPassword(password);
  users[userId] = { email, salt, hash, createdAt: Date.now() };
  const token = newToken();
  tokens[token] = userId;
  persistUsers();
  res.json({ token });
});

app.post('/auth/login', (req, res) => {
  const email = String((req.body && req.body.email) || '').trim().toLowerCase();
  const password = String((req.body && req.body.password) || '');
  const entry = Object.entries(users).find(([, u]) => u.email === email);
  if (!entry || !verifyPassword(password, entry[1].salt, entry[1].hash)) {
    return res.status(401).json({ error: 'الإيميل أو كلمة المرور غلط' });
  }
  const token = newToken();
  tokens[token] = entry[0];
  persistUsers();
  res.json({ token });
});

// ---------- مزامنة البيانات ----------
app.get('/snapshot', auth, (req, res) => {
  res.json({ snapshot: snapshots[req.userId] || {} });
});

app.post('/sync', auth, (req, res) => {
  const incoming = (req.body && req.body.snapshot) || {};
  const current = snapshots[req.userId] || {};
  Object.keys(incoming).forEach(key => {
    const inItem = incoming[key];
    const curItem = current[key];
    if (!curItem || (inItem && inItem.u >= curItem.u)) current[key] = inItem;
  });
  snapshots[req.userId] = current;
  persistSnapshots();
  res.json({ snapshot: current });
});

app.delete('/account/data', auth, (req, res) => {
  const userId = req.userId;
  delete snapshots[userId];
  delete subscriptions[userId];
  delete queue[userId];
  delete users[userId];
  Object.keys(tokens).forEach(t => { if (tokens[t] === userId) delete tokens[t]; });
  persistSnapshots(); persistSubs(); persistQueue(); persistUsers();
  res.json({ ok: true });
});

// ---------- Push ----------
app.get('/push/vapid-public-key', (req, res) => {
  res.json({ key: VAPID_PUBLIC_KEY });
});

// تسجيل اشتراك الجهاز في الـ Push (بيتنفذ بعد إذن الإشعارات)
app.post('/push/subscribe', auth, (req, res) => {
  const sub = req.body && req.body.subscription;
  if (!sub || !sub.endpoint) return res.status(400).json({ error: 'subscription غير صالح' });
  const list = subscriptions[req.userId] || [];
  const filtered = list.filter(s => s.endpoint !== sub.endpoint);
  filtered.push(sub);
  subscriptions[req.userId] = filtered;
  persistSubs();
  res.json({ ok: true });
});

app.post('/push/unsubscribe', auth, (req, res) => {
  const endpoint = req.body && req.body.endpoint;
  const list = subscriptions[req.userId] || [];
  subscriptions[req.userId] = list.filter(s => s.endpoint !== endpoint);
  persistSubs();
  res.json({ ok: true });
});

// العميل بيبعت قائمة التنبيهات المطلوبة النهارده (وقت + عنوان + نص) كل ما البيانات تتغيّر
// السيرفر بيستبدل قائمة اليوم بالكامل بكل مزامنة (idempotent)
app.post('/push/queue', auth, (req, res) => {
  const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
  const clean = items
    .filter(it => it && it.id && it.time && it.title)
    .map(it => ({
      id: String(it.id).slice(0, 80),
      time: String(it.time),
      title: String(it.title).slice(0, 120),
      body: String(it.body || '').slice(0, 300),
      tag: String(it.tag || 'pov').slice(0, 60),
    }));
  queue[req.userId] = clean;
  persistQueue();
  res.json({ ok: true, count: clean.length });
  app.listen(PORT, '0.0.0.0', () => {
  console.log('=== POV SERVER LIVE ===');
  console.log('PORT:', PORT);
    app.listen(PORT, '0.0.0.0', () => {

  console.log('=== POV SERVER LIVE ===');

  console.log('PORT:', PORT);

app.listen(PORT, '0.0.0.0', () => {
  console.log('POV server running on port ' + PORT);
});

// ---------------- محرك إرسال الإشعارات ----------------
// كل 30 ثانية: يدور على كل مستخدم عنده عناصر في الطابور معادها استحق، يبعتها بوش، ويشيلها
async function tick() {
  const now = Date.now();
  let changedQueue = false, changedSubs = false;
  for (const userId of Object.keys(queue)) {
    const items = queue[userId] || [];
    if (!items.length) continue;
    const due = items.filter(it => new Date(it.time).getTime() <= now && now - new Date(it.time).getTime() < 2 * 60 * 60 * 1000);
    const stillPending = items.filter(it => new Date(it.time).getTime() > now);
    // لو فيه عنصر فات معاده بأكتر من ساعتين، بنشيله من غير ما نبعته (بقى قديم)
    if (due.length) {
      changedQueue = true;
      const subs = subscriptions[userId] || [];
      for (const item of due) {
        for (const sub of subs.slice()) {
          try {
            await webpush.sendNotification(sub, JSON.stringify({
              title: item.title, body: item.body, tag: item.tag,
            }));
          } catch (err) {
            if (err && (err.statusCode === 404 || err.statusCode === 410)) {
              subscriptions[userId] = (subscriptions[userId] || []).filter(s => s.endpoint !== sub.endpoint);
              changedSubs = true;
            } else {
              console.error('push error for user', userId, err && err.message);
            }
          }
        }
      }
    }
    if (stillPending.length !== items.length) {
      queue[userId] = stillPending;
      changedQueue = true;
    }
  }
  if (changedQueue) persistQueue();
  if (changedSubs) persistSubs();
}
setInterval(() => { tick().catch(e => console.error('tick error', e)); }, 30 * 1000);
