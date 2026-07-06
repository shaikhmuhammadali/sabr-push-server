'use strict';
/* ─────────────────────────────────────────────────────────────────────────────
   Sabr Push + Voice Server
   ─────────────────────────────────────────────────────────────────────────────
   One tiny, self-owned server that does TWO independent jobs for the Sabr app:

   1) /tts  — voices ANY Arabic (hadith, dhikr, dua) for the app's "Recite" button.
              Qur'an ayahs already play a real reciter (Al-Afasy etc.) straight from
              the app with no server. Hadith & short dhikr were never recorded by a
              reciter, and a computer usually has no Arabic voice — so the app hands
              that text here and this endpoint speaks it back as audio. It proxies a
              real TTS and re-serves it with audio/mpeg + open CORS, which the
              browser accepts (the raw Google endpoint is blocked cross-origin).
              >>> This works with ZERO configuration. No keys needed. <<<

   2) push  — stores each subscriber's precomputed reminder schedule and fires the
              notifications at the right moment, even when the app is closed. This
              half is OPTIONAL and only turns on if you set VAPID keys.

   Deploys on any free host (Render / Railway / Fly / Cyclic / Glitch). No database,
   no native modules — just Node 18+. The app re-uploads its schedule every time it
   opens, so nothing important is lost if the host restarts.
   ───────────────────────────────────────────────────────────────────────────── */

try { require('dotenv').config(); } catch (_) { /* dotenv is optional */ }

const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const webpush = require('web-push');
const googleTTS = require('google-tts-api');

let alertTelegram = async () => {};
try { ({ alertTelegram } = require('./alert')); } catch (_) { /* telegram alerts optional */ }

// ── config ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const STORE = process.env.STORE_FILE || path.join(__dirname, 'data', 'subs.json');
const SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@example.com';
// accept both naming styles so any older .env keeps working
let PUBLIC = process.env.VAPID_PUBLIC || process.env.VAPID_PUBLIC_KEY || '';
let PRIVATE = process.env.VAPID_PRIVATE || process.env.VAPID_PRIVATE_KEY || '';
const APP_KEY = process.env.APP_KEY || '';           // optional shared secret for writes
const ALLOWED = (process.env.ALLOWED_ORIGINS || '')  // optional CORS allow-list (empty = allow all)
  .split(',').map((s) => s.trim()).filter(Boolean);

// Zero-config push: if no keys were provided, load previously generated ones — or
// generate a fresh pair and persist it beside the subscriber store. Deploying this
// server therefore needs NO environment setup at all. (If a free host wipes the disk
// on redeploy, new keys are generated; the app detects the change on its next open
// and silently re-subscribes, so reminders keep working.)
if (!PUBLIC || !PRIVATE) {
  const KEYFILE = process.env.VAPID_FILE || path.join(path.dirname(STORE), 'vapid.json');
  try {
    const k = JSON.parse(fs.readFileSync(KEYFILE, 'utf8'));
    if (k.publicKey && k.privateKey) { PUBLIC = k.publicKey; PRIVATE = k.privateKey; }
  } catch (_) { /* no keyfile yet */ }
  if (!PUBLIC || !PRIVATE) {
    const k = webpush.generateVAPIDKeys();
    PUBLIC = k.publicKey; PRIVATE = k.privateKey;
    try {
      fs.mkdirSync(path.dirname(KEYFILE), { recursive: true });
      fs.writeFileSync(KEYFILE, JSON.stringify(k));
      console.log('[vapid] generated new keys (persisted to ' + KEYFILE + ')');
    } catch (e) { console.error('[vapid] keys generated but NOT persisted:', e.message); }
  }
}

const PUSH_ENABLED = Boolean(PUBLIC && PRIVATE);
if (PUSH_ENABLED) webpush.setVapidDetails(SUBJECT, PUBLIC, PRIVATE);

// ── persistence: a single JSON file, debounced + atomic write ─────────────────
// shape: { [endpoint]: { subscription, schedule:[{ts,title,body,tag,fired}], updatedAt } }
let subs = {};
try {
  fs.mkdirSync(path.dirname(STORE), { recursive: true });
  subs = JSON.parse(fs.readFileSync(STORE, 'utf8'));
} catch (_) { subs = {}; }

let saveTimer = null;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      const tmp = STORE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(subs));
      fs.renameSync(tmp, STORE);                       // atomic: never leaves a half-written file
    } catch (e) { console.error('[store] save failed:', e.message); }
  }, 400);
}

// ── app + hardening ───────────────────────────────────────────────────────────
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);                             // correct client IPs behind a host's proxy
app.use(helmet({
  // CRITICAL: the app is a static site on another origin loading /tts audio.
  // helmet's default CORP (same-origin) + COEP would block that — turn them off.
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: false,                        // this is a JSON/audio API, not a web page
}));
app.use(express.json({ limit: '400kb' }));             // the schedule can be ~150KB; 20kb would reject it

// open CORS (no credentials are ever used). If ALLOWED_ORIGINS is set, reflect only those.
app.use((req, res, next) => {
  const origin = req.get('Origin');
  const allow = (ALLOWED.length === 0) ? '*' : (origin && ALLOWED.includes(origin) ? origin : ALLOWED[0]);
  res.set('Access-Control-Allow-Origin', allow);
  res.set('Vary', 'Origin');
  res.set('Access-Control-Allow-Headers', 'Content-Type, X-App-Key');
  res.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// generous general limiter; /health is exempt so uptime pings never trip it
app.use(rateLimit({
  windowMs: 60 * 1000, max: 240, standardHeaders: true, legacyHeaders: false,
  skip: (req) => req.path === '/health',
}));
const writeLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });

function guard(req, res) {
  if (!APP_KEY) return true;                            // no key configured → open (personal use)
  const provided = Buffer.from(req.get('X-App-Key') || '');
  const expected = Buffer.from(APP_KEY);
  const ok = provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
  if (!ok) { res.status(401).json({ error: 'bad app key' }); return false; }
  return true;
}

// ── routes ─────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.type('text').send(
  'Sabr Push + Voice Server is running.\n' +
  'Voice (recite): GET /tts?tl=ar&q=<arabic>   [always on]\n' +
  'Push: /vapid /subscribe /unsubscribe /tick   [' + (PUSH_ENABLED ? 'on' : 'off — set VAPID keys to enable') + ']\n'
));

app.get('/health', (req, res) => res.json({
  ok: true, tts: true, push: PUSH_ENABLED, subs: Object.keys(subs).length, time: new Date().toISOString(),
}));

/* ── 1) VOICE: /tts — the "recite everything" endpoint (zero-config) ──────────── */
const _ttsCache = new Map();                            // key -> Buffer (bounded LRU)
const TTS_CACHE_MAX = 800;
function cacheGet(k) {
  const v = _ttsCache.get(k);
  if (v) { _ttsCache.delete(k); _ttsCache.set(k, v); }  // touch → most-recently-used
  return v;
}
function cacheSet(k, v) {
  _ttsCache.set(k, v);
  while (_ttsCache.size > TTS_CACHE_MAX) _ttsCache.delete(_ttsCache.keys().next().value);
}

app.get('/tts', async (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 300);
  const tl = String(req.query.tl || 'ar').slice(0, 5);
  if (!q) return res.status(400).json({ error: 'missing q' });
  const key = tl + '|' + q;
  try {
    let buf = cacheGet(key);
    if (!buf) {
      // getAllAudioUrls splits long text into <=200-char chunks; we fetch each and
      // concatenate the MP3 frames server-side into one seamless clip.
      const parts = googleTTS.getAllAudioUrls(q, {
        lang: tl, slow: false, host: 'https://translate.google.com', splitPunct: '،.۔!؟\n',
      });
      const buffers = [];
      for (const p of parts) {
        const r = await fetch(p.url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        if (!r.ok) return res.status(502).json({ error: 'tts upstream ' + r.status });
        buffers.push(Buffer.from(await r.arrayBuffer()));
      }
      buf = Buffer.concat(buffers);
      if (buf.length) cacheSet(key, buf);
    }
    res.set('Content-Type', 'audio/mpeg');
    res.set('Cache-Control', 'public, max-age=604800, immutable');
    res.set('ETag', '"' + crypto.createHash('sha1').update(key).digest('hex') + '"');
    res.end(buf);
  } catch (e) {
    console.error('[tts]', e.message);
    res.status(502).json({ error: 'tts failed' });
  }
});

/* ── 2) PUSH: only meaningful when VAPID keys are set ─────────────────────────── */
function requirePush(req, res) {
  if (!PUSH_ENABLED) { res.status(503).json({ error: 'push disabled — set VAPID keys to enable background reminders' }); return false; }
  return true;
}

app.get('/vapid', (req, res) => {
  if (!requirePush(req, res)) return;
  res.json({ publicKey: PUBLIC });
});

app.post('/subscribe', writeLimiter, (req, res) => {
  if (!requirePush(req, res)) return;
  if (!guard(req, res)) return;
  const { subscription, schedule } = req.body || {};
  if (!subscription || typeof subscription.endpoint !== 'string' || !subscription.endpoint.startsWith('https://')) {
    return res.status(400).json({ error: 'invalid subscription' });
  }
  const now = Date.now();
  const clean = Array.isArray(schedule)
    ? schedule
        .filter((s) => s && typeof s.ts === 'number' && s.ts > now - 60000)
        .map((s) => ({
          ts: s.ts,
          title: String(s.title || 'صبر').slice(0, 120),
          body: String(s.body || '').slice(0, 300),
          tag: String(s.tag || 'sabr').slice(0, 40),
          fired: false,
        }))
        .sort((a, b) => a.ts - b.ts)
        .slice(0, 400)
    : [];
  subs[subscription.endpoint] = { subscription, schedule: clean, updatedAt: now };
  save();
  res.json({ ok: true, queued: clean.length });
});

app.post('/unsubscribe', writeLimiter, (req, res) => {
  const ep = req.body && (req.body.endpoint || (req.body.subscription && req.body.subscription.endpoint));
  if (ep && subs[ep]) { delete subs[ep]; save(); }
  res.json({ ok: true });
});

// ── scheduler: fire everything due. Internal every 60s + /tick for external cron ──
let _ticking = false;
async function tick() {
  if (!PUSH_ENABLED || _ticking) return;
  _ticking = true;
  try {
    const now = Date.now();
    const dead = [];
    let changed = false;
    for (const ep of Object.keys(subs)) {
      const rec = subs[ep];
      if (!rec || !Array.isArray(rec.schedule)) continue;
      const due = rec.schedule.filter((s) => !s.fired && s.ts <= now && s.ts > now - 15 * 60000);
      for (const item of due) {
        item.fired = true; changed = true;
        try {
          await webpush.sendNotification(rec.subscription, JSON.stringify({ title: item.title, body: item.body, tag: item.tag }));
        } catch (err) {
          if (err && (err.statusCode === 404 || err.statusCode === 410)) { dead.push(ep); break; }
        }
      }
      const before = rec.schedule.length;
      rec.schedule = rec.schedule.filter((s) => s.ts > now - 60 * 60000); // prune >1h old
      if (rec.schedule.length !== before) changed = true;
    }
    dead.forEach((ep) => { delete subs[ep]; changed = true; });
    if (changed) save();
  } finally { _ticking = false; }
}
app.all('/tick', async (req, res) => { await tick().catch((e) => console.error('[tick]', e.message)); res.json({ ok: true, at: Date.now() }); });
if (PUSH_ENABLED) setInterval(() => tick().catch((e) => console.error('[tick]', e.message)), 60000);

// ── 404 + error handler (never leak internals) ────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'not found' }));
app.use((err, req, res, next) => {
  console.error('[server error]', err && err.message);
  res.status(500).json({ error: 'internal error' });
});

// ── crash safety ───────────────────────────────────────────────────────────────
process.on('uncaughtException', (err) => { console.error('[uncaughtException]', err); alertTelegram('uncaughtException: ' + (err && err.message)); });
process.on('unhandledRejection', (reason) => { console.error('[unhandledRejection]', reason); alertTelegram('unhandledRejection: ' + reason); });

app.listen(PORT, () => {
  console.log(`\nSabr Push + Voice Server on :${PORT}`);
  console.log(`  Voice /tts : ON  (recite works with no extra setup)`);
  console.log(`  Push       : ${PUSH_ENABLED ? 'ON' : 'OFF (set VAPID_PUBLIC + VAPID_PRIVATE to enable)'}`);
  console.log(`  Subscribers loaded: ${Object.keys(subs).length}\n`);
  console.log(`  In the app → Settings → paste this server's URL to enable recite everywhere.\n`);
});
