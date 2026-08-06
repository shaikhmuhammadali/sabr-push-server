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

// ── email (for "email me a reset code") ───────────────────────────────────────
// Two transports, tried in priority order:
//   1. Brevo HTTPS API (BREVO_API_KEY) — sends over port 443, so it works even on hosts
//      that block outbound SMTP. Render's free tier blocks ports 25/465/587, which makes
//      a direct Gmail/SMTP connection time out; this path sidesteps that entirely.
//   2. SMTP via nodemailer (SMTP_* env) — used when Brevo isn't set and the host DOES allow
//      SMTP (a paid Render instance, or self-hosting).
// With neither configured, the email-reset routes report they're not set up (the app still
// works fully offline/on-device; only the "email me a code" convenience is unavailable).
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';
let mailer = null;
const MAIL_FROM = process.env.MAIL_FROM || process.env.SMTP_USER || '';
// Split a `"Name" <email>` (or a bare `email`) MAIL_FROM into the parts the Brevo API wants.
const FROM = (() => {
  const m = /^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/.exec(MAIL_FROM);
  if (m) return { name: (m[1].trim() || 'Sirat Khushu'), email: m[2].trim() };
  return { name: 'Sirat Khushu', email: MAIL_FROM.trim() };
})();
(() => {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) return;
  try {
    const nodemailer = require('nodemailer');
    mailer = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT) || 587,
      secure: /^(1|true|yes)$/i.test(process.env.SMTP_SECURE || '') || Number(process.env.SMTP_PORT) === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
  } catch (e) { console.error('[mail] nodemailer not installed:', e.message); }
})();
const MAIL_ENABLED = () => !!(BREVO_API_KEY && FROM.email) || !!mailer;
console.log('[mail] ' + (BREVO_API_KEY && FROM.email
  ? 'Brevo API configured — email password reset is ON (from ' + FROM.email + ')'
  : mailer ? 'SMTP configured — email password reset is ON'
  : 'no email transport set — "email me a code" reset is OFF'));

// Send one email (plaintext + optional HTML). Prefers the Brevo HTTPS API, falls back to SMTP.
// Throws on failure so callers can decide whether that's fatal. Bounded by a 15s timeout so a
// stalled network surfaces as a clean error instead of hanging the whole HTTP request.
async function sendMailRaw({ to, subject, text, html }) {
  if (BREVO_API_KEY && FROM.email) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15000);
    try {
      const res = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: { 'api-key': BREVO_API_KEY, 'content-type': 'application/json', 'accept': 'application/json' },
        body: JSON.stringify(Object.assign(
          { sender: FROM, to: [{ email: to }], subject, textContent: text },
          html ? { htmlContent: html } : {})),
        signal: ctrl.signal,
      });
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error('Brevo ' + res.status + ': ' + body.slice(0, 300));
      }
    } finally { clearTimeout(timer); }
    return;
  }
  if (mailer) { await mailer.sendMail({ from: MAIL_FROM, to, subject, text, html }); return; }
  throw new Error('no mail transport configured');
}

const escHtml = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Fire-and-forget security alert: tell the account owner their password just changed, so an
// unexpected change (e.g. from a stolen session token) is noticed and can be undone via email
// recovery. Never blocks or fails the password change — a mail error is only logged.
function sendPasswordChangedAlert(u, req) {
  try {
    if (!MAIL_ENABLED() || !u || !u.email) return;
    const name = u.username || 'there';
    const when = new Date().toUTCString();
    const ip = (req && (req.ip || (req.headers && req.headers['x-forwarded-for']))) || 'unknown';
    sendMailRaw({
      to: u.email,
      subject: 'Your Sirat Khushu password was changed',
      text:
        'Assalamu alaikum ' + name + ',\n\n' +
        'This is a security notice: the password for your Sirat Khushu account was just changed.\n\n' +
        'When: ' + when + '\n' +
        'Request origin (IP): ' + ip + '\n\n' +
        'If this was you, no action is needed — every other signed-in device has been logged out for safety.\n\n' +
        'If this was NOT you, act now: open Sirat Khushu, go to Log in > "Forgot password?", and reset your ' +
        'password using the code we email you. That immediately locks out whoever made this change.\n\n' +
        '— Sirat Khushu',
      html:
        '<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:520px;margin:0 auto;background:#0a0e14;color:#e9e3d2;border:1px solid rgba(217,180,91,.3);border-radius:16px;padding:26px 24px">' +
        '<div style="text-align:center;color:#e6c169;font-size:12px;letter-spacing:.22em;text-transform:uppercase;font-weight:700">Security notice</div>' +
        '<h2 style="text-align:center;color:#f4ecd8;font-weight:700;margin:10px 0 6px;font-size:20px">Your password was changed</h2>' +
        '<p style="color:#c8c2b0;line-height:1.6;font-size:14px">Assalamu alaikum <b>' + escHtml(name) + '</b>, the password for your Sirat Khushu account was just changed.</p>' +
        '<div style="background:rgba(217,180,91,.08);border:1px solid rgba(217,180,91,.25);border-radius:12px;padding:12px 14px;font-size:13px;color:#cfc7b4;line-height:1.8">' +
        '<div><b style="color:#e6c169">When:</b> ' + escHtml(when) + '</div>' +
        '<div><b style="color:#e6c169">Request origin (IP):</b> ' + escHtml(String(ip)) + '</div></div>' +
        '<p style="color:#c8c2b0;line-height:1.6;font-size:14px;margin-top:16px">If this was you, no action is needed — every other signed-in device was logged out for safety.</p>' +
        '<p style="color:#e8a0a8;line-height:1.6;font-size:14px"><b>If this wasn’t you:</b> open Sirat Khushu, go to <b>Log in &rarr; Forgot password?</b> and reset with the emailed code. That immediately locks out whoever made the change.</p>' +
        '<p style="text-align:center;color:#8a94a6;font-size:12px;margin-top:22px">— Sirat Khushu</p></div>',
    }).catch(e => console.error('[mail] password-change alert failed:', e.message));
  } catch (e) { console.error('[mail] password-change alert error:', e.message); }
}

// ── config ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const STORE = process.env.STORE_FILE || path.join(__dirname, 'data', 'subs.json');
// Declared here (not down in the accounts section) so the shared store can be created
// alongside STORE below — a `const` cannot be referenced before its definition runs.
const USERS_STORE = process.env.USERS_FILE || path.join(path.dirname(STORE), 'users.json');
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

// ── persistence: debounced + atomic, file-backed or Postgres-backed ───────────
// shape: { [endpoint]: { subscription, schedule:[{ts,title,body,tag,fired}], updatedAt } }
// store.js picks the backend: JSON files by default, Postgres when DATABASE_URL is
// set — because free hosts wipe the filesystem on every restart, which would erase
// every account. Both stores are loaded in startServer() before the port opens.
const ANALYTICS_STORE = process.env.ANALYTICS_FILE || path.join(path.dirname(STORE), 'analytics.json');
const store = require('./store').createStore({ subs: STORE, users: USERS_STORE, analytics: ANALYTICS_STORE });
let subs = {};
// Anonymous, opt-in usage analytics (only ever written when a user turns tracking on in the app).
// Shape: users{ id:{c,a,d,ct} } · surahs{ num:count } · days{ yyyymmdd:{ id:1 } }. All aggregates,
// no per-event log, no personal data, no account linkage. Bounded + pruned (see trackPrune).
let analytics = { users: Object.create(null), surahs: Object.create(null), days: Object.create(null) };

// ── app + hardening ───────────────────────────────────────────────────────────
const app = express();
app.disable('x-powered-by');
// How many proxies sit in front of us (for correct client IPs / rate-limit keys). Managed hosts
// like Render/Railway put exactly ONE proxy in front, so the default is 1. On a BARE server with
// no fronting proxy, set TRUST_PROXY=0 — otherwise a client could spoof X-Forwarded-For to dodge
// the rate limiters. Accepts a number, or 'false'/'0' to trust none.
const TP = process.env.TRUST_PROXY;
app.set('trust proxy', (TP === undefined) ? 1 : (/^(false|0|off|no)$/i.test(TP) ? false : (isNaN(+TP) ? TP : +TP)));
app.use(helmet({
  // CRITICAL: the app is a static site on another origin loading /tts audio.
  // helmet's default CORP (same-origin) + COEP would block that — turn them off.
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: false,                        // this is a JSON/audio API, not a web page
}));
app.use(express.json({ limit: '1200kb' }));            // push schedule ~150KB; account blob cap is 500KB (UTF-8 can ~2x that in bytes)

// open CORS (no credentials are ever used). If ALLOWED_ORIGINS is set, reflect only those.
app.use((req, res, next) => {
  const origin = req.get('Origin');
  const allow = (ALLOWED.length === 0) ? '*' : (origin && ALLOWED.includes(origin) ? origin : ALLOWED[0]);
  res.set('Access-Control-Allow-Origin', allow);
  res.set('Vary', 'Origin');
  res.set('Access-Control-Allow-Headers', 'Content-Type, X-App-Key, Authorization');
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
  'Push: /vapid /subscribe /unsubscribe /tick   [' + (PUSH_ENABLED ? 'on' : 'off — set VAPID keys to enable') + ']\n' +
  'Accounts: /auth/signup /auth/login /auth/sync /auth/password /auth/logout   [always on]\n' +
  'Email reset: /auth/forgot-email /auth/reset-email   [' + (MAIL_ENABLED() ? 'on' : 'off — set SMTP_* env to enable') + ']\n'
));

app.get('/health', (req, res) => res.json({
  ok: true, tts: true, push: PUSH_ENABLED, auth: true, emailReset: MAIL_ENABLED(), subs: Object.keys(subs).length,
  users: Object.keys(accounts.users).length, time: new Date().toISOString(),
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

/* ── 2) ACCOUNTS: cloud login + data sync (the "official" restore path) ─────────
   The app signs users up here; on any device they log in with name + password and
   the server hands back their saved data blob. Passwords are scrypt-hashed with a
   per-user salt; sessions are random 256-bit tokens stored hashed. The blob is the
   app's own settings snapshot — stored as-is, only ever returned to its owner.
   Concurrency is guarded by a per-user `rev`: /auth/sync must send the rev it based
   its edit on, and a stale rev is rejected (409) instead of clobbering newer data. */
// (USERS_STORE is declared up in the config block, next to STORE.)
// null-prototype maps so a username like "constructor"/"__proto__" can never collide with an
// inherited Object.prototype member (which would otherwise 409 or crash signup/login).
let accounts = { users: Object.create(null), tokens: Object.create(null) };
store.bind(accounts, subs);
store.bindAnalytics(analytics);

/* Persist ONE account, not the whole table. This is the hot path: it runs on every
   sync, so its cost must not grow with the number of users. (The old whole-store
   rewrite measured 197ms of blocked event loop at 1,000 users x 100KB blobs.)
   `saveTokens` is separate because tokens are small and always written together. */
const saveUser = (key) => store.saveUser(key);
const saveTokens = () => store.saveTokens();
const saveAccounts = () => store.saveAllUsers();   // full rewrite — rare (admin actions)

const scryptHex = (pw, salt) => new Promise((resolve, reject) =>
  crypto.scrypt(String(pw), salt, 64, (e, k) => (e ? reject(e) : resolve(k.toString('hex')))));
const DUMMY_SALT = crypto.randomBytes(16).toString('hex');   // fixed per-process salt to equalize login timing when a username is absent (blocks user enumeration)
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const TOKEN_TTL = 180 * 24 * 3600 * 1000;                // devices stay logged in ~6 months
const BLOB_MAX = 500000;                                  // per-user data cap, in BYTES (~500 KB)
const PW_MAX = 256;                                       // cap password length (scrypt cost is caller-controlled otherwise)
// Password-reset throttles kept on a PERSISTENT per-account guard (u.resetGuard) so deleting the
// resetCode can never reset them — closes the 429 → delete-code → new-code brute-force loop.
const RESET_COOLDOWN_MS = 60 * 1000;                      // min gap between codes for one account
const RESET_CODES_PER_DAY = 6;                            // max codes emailed to one account per 24h
const RESET_MAX_FAILS = 10;                               // wrong-code attempts before reset locks
const RESET_FAIL_WINDOW_MS = 60 * 60 * 1000;              // wrong-code lockout window
// Signup abuse guards: a global account ceiling (a per-IP creation limiter is added below).
const MAX_ACCOUNTS = parseInt(process.env.MAX_ACCOUNTS, 10) || 5000;   // global backstop; raise via env as usage grows
let _signupCeilAlerted = false;
const normUser = (u) => String(u || '').trim().replace(/\s+/g, ' ').slice(0, 40);
const normEmail = (e) => String(e || '').trim().toLowerCase().slice(0, 254);
const has = (obj, k) => Object.prototype.hasOwnProperty.call(obj, k);
// Is this email already on some OTHER account? Signup refuses duplicates, because password
// recovery resolves accounts by email and duplicates make that lookup ambiguous.
function emailTaken(email, exceptKey) {
  const e = normEmail(email); if (!e) return false;
  for (const key of Object.keys(accounts.users)) {
    if (key === exceptKey) continue;
    const u = accounts.users[key];
    if (u && u.email && normEmail(u.email) === e) return true;
  }
  return false;
}

// Look up an account by its registered email (case-insensitive). Password recovery is email-based:
// the user types their email, the server finds the matching account and mails it a code.
// Signup now enforces uniqueness, but records created before that could still collide — so pick
// the OLDEST match deterministically rather than "whichever key iterates first". Insertion order
// is not a security property: without this, who receives a reset code could depend on the order
// accounts happened to be created in.
function findByEmail(email) {
  const e = normEmail(email); if (!e) return null;
  let best = null;
  for (const key of Object.keys(accounts.users)) {
    const u = accounts.users[key];
    if (!u || !u.email || normEmail(u.email) !== e) continue;
    if (!best || (u.createdAt || 0) < (best.u.createdAt || 0)) best = { key, u };
  }
  return best;
}

function issueToken(key) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  for (const th of Object.keys(accounts.tokens)) if (accounts.tokens[th].exp < now) delete accounts.tokens[th];
  accounts.tokens[sha256hex(token)] = { u: key, exp: now + TOKEN_TTL };
  saveTokens();                     // login must not rewrite every account
  return token;
}
// Drop every token for this user except (optionally) the one making the request — used on a
// password change so a lost/stolen device that was signed in is actually evicted.
function revokeTokens(key, keepHash) {
  for (const th of Object.keys(accounts.tokens)) {
    if (accounts.tokens[th].u === key && th !== keepHash) delete accounts.tokens[th];
  }
}
function tokenHashFromReq(req) {
  const m = /^Bearer\s+([a-f0-9]{64})$/i.exec(req.get('Authorization') || '');
  return m ? sha256hex(m[1].toLowerCase()) : null;
}
function userFromReq(req) {
  const th = tokenHashFromReq(req);
  if (!th || !has(accounts.tokens, th)) return null;
  const rec = accounts.tokens[th];
  if (!rec || rec.exp < Date.now()) return null;
  const user = has(accounts.users, rec.u) ? accounts.users[rec.u] : null;
  return user ? { key: rec.u, user, th } : null;
}
const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
// Stricter, separate per-IP cap on NEW account creation — signup is a one-time act, so a flood of
// unauthenticated 500 KB-blob signups (which the general 20/min auth limiter alone permits) can't
// pile persistence-amplified junk accounts onto the free instance.
const signupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'too many sign-ups from here — please try again later' } });

// If APP_KEY is set the whole server is private to the owner's app, so gate /auth too (the app
// sends the same X-App-Key it uses for push). With no APP_KEY, accounts are open (public app).
function authGuard(req, res, next) { if (!guard(req, res)) return; next(); }

app.post('/auth/signup', signupLimiter, authLimiter, authGuard, async (req, res) => {
  try {
    const { username, email, password, data, secQ, secA } = req.body || {};
    const name = normUser(username);
    const key = name.toLowerCase();
    if (name.length < 2) return res.status(400).json({ error: 'username too short' });
    if (typeof password !== 'string' || password.length < 6) return res.status(400).json({ error: 'password too short (6+ characters)' });
    if (password.length > PW_MAX) return res.status(400).json({ error: 'password too long' });
    if (has(accounts.users, key)) return res.status(409).json({ error: 'username taken' });
    // Global ceiling: a new account past the cap is refused (fail closed) and the owner is alerted once,
    // so mass-signup abuse can never fill the (free) database unbounded.
    if (Object.keys(accounts.users).length >= MAX_ACCOUNTS) {
      if (!_signupCeilAlerted) { _signupCeilAlerted = true; try { alertTelegram('signup ceiling reached (' + MAX_ACCOUNTS + ' accounts) — new signups refused'); } catch (_) {} }
      return res.status(503).json({ error: 'sign-ups are temporarily closed' });
    }
    // Email must be unique too. Password recovery resolves an account BY EMAIL, so two
    // accounts sharing one address make that lookup ambiguous: reset codes for one person
    // land in the other's inbox, and whoever loses the tie can never recover their account.
    // (Same reason a stranger must not be able to register with someone else's address.)
    if (typeof email === 'string' && email.trim() && emailTaken(email, key)) {
      return res.status(409).json({ error: 'that email is already registered' });
    }
    let blob = null;
    if (data && typeof data === 'object') {
      blob = JSON.stringify(data);
      if (Buffer.byteLength(blob) > BLOB_MAX) return res.status(413).json({ error: 'data too large' });
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const rec = {
      username: name,
      email: (typeof email === 'string' && email.trim()) ? email.trim().slice(0, 120) : null,
      salt, hash: await scryptHex(password, salt),
      data: blob, rev: 1, fails: null, createdAt: Date.now(), updatedAt: Date.now(),
    };
    // Optional recovery question — lets a user reset their password on a NEW device (where the
    // local security answer isn't available). Stored like a password: server-salted scrypt hash.
    await attachRecovery(rec, secQ, secA);
    accounts.users[key] = rec;
    saveUser(key);
    const token = issueToken(key);
    res.json({ ok: true, token, username: name, rev: 1 });
  } catch (e) { console.error('[auth/signup]', e.message); res.status(500).json({ error: 'internal error' }); }
});

// Store (or clear) a recovery question + answer on a user record. The answer arrives already
// normalized by the client; we keep only its scrypt hash.
async function attachRecovery(rec, secQ, secA) {
  if (typeof secQ === 'string' && secQ.trim() && typeof secA === 'string' && secA.length) {
    rec.secQ = secQ.trim().slice(0, 200);
    rec.secASalt = crypto.randomBytes(16).toString('hex');
    rec.secAHash = await scryptHex(secA.slice(0, 200), rec.secASalt);
  }
}

// NOTE: the old security-question routes /auth/forgot and /auth/reset were REMOVED.
// Recovery is now email-only (/auth/forgot-email + /auth/reset-email). Dropping /auth/forgot
// also closes a username-enumeration hole (it used to return the account's question or a 404).

// Shared tail for any successful reset: re-hash password, evict all devices, return a fresh session.
async function finishReset(res, key, u, newPassword) {
  u.salt = crypto.randomBytes(16).toString('hex');
  u.hash = await scryptHex(newPassword, u.salt);
  u.updatedAt = Date.now();
  delete u.resetCode;
  delete u.resetGuard;      // a successful reset clears all throttle / lockout state
  saveUser(key);            // CRITICAL: persist the NEW hash. issueToken() only saves the tokens
                            // row, so on the Postgres backend the user row would keep the OLD hash
                            // and the reset would silently revert after any restart — locking the
                            // user out. (/auth/password already does saveUser(); this path missed it.)
  revokeTokens(key, null);
  const token = issueToken(key);
  let dataObj = null; try { dataObj = u.data ? JSON.parse(u.data) : null; } catch (_) {}
  res.json({ ok: true, token, username: u.username, email: u.email, data: dataObj, rev: u.rev || 0 });
  sendPasswordChangedAlert(u, res.req);                  // notify the owner their password changed
}

// Email a 6-digit reset code to the account's email (if email reset is configured).
app.post('/auth/forgot-email', authLimiter, authGuard, async (req, res) => {
  try {
    const body = req.body || {};
    // Primary path: the user types their email → find the account by email.
    // Backward-compatible fallback: {username} still works for older clients.
    let u = null, uKey = null;
    if (body.email) { const f = findByEmail(body.email); if (f) { u = f.u; uKey = f.key; } }
    else { const k = normUser(body.username).toLowerCase(); if (has(accounts.users, k)) { u = accounts.users[k]; uKey = k; } }
    if (!MAIL_ENABLED()) return res.status(503).json({ error: 'email reset is not set up on this server' });
    // Always answer the same way whether or not the email matches an account (no enumeration via this route).
    if (u && u.email) {
      const now = Date.now();
      const g = u.resetGuard || (u.resetGuard = {});
      if (!g.dayStart || (now - g.dayStart) > 86400000) { g.dayStart = now; g.dayCount = 0; }         // roll the 24h code-count window
      if (g.failStart && (now - g.failStart) > RESET_FAIL_WINDOW_MS) { g.fails = 0; g.failStart = 0; } // expire the wrong-code lockout
      // PERSISTENT guards that survive resetCode deletion, so the 429 → delete-code → new-code loop can
      // no longer reset the throttle: a 60s cooldown, a per-day code cap, and a wrong-code lockout.
      const _blocked = ((g.fails || 0) >= RESET_MAX_FAILS)
        || (g.lastSentAt && (now - g.lastSentAt) < RESET_COOLDOWN_MS)
        || ((g.dayCount || 0) >= RESET_CODES_PER_DAY);
      if (!_blocked) {
        const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
        u.resetCode = { hash: sha256hex(code), exp: now + 15 * 60000, tries: 0, sentAt: now };
        g.lastSentAt = now; g.dayCount = (g.dayCount || 0) + 1;
        saveUser(uKey);
        try {
          await sendMailRaw({
            to: u.email,
            subject: 'Your Sirat Khushu password reset code',
            text: 'Assalamu alaikum,\n\nYour password reset code is: ' + code + '\n\nIt expires in 15 minutes. If you did not request this, you can safely ignore this email.',
            html: '<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:480px;margin:0 auto;background:#0a0e14;color:#e9e3d2;border:1px solid rgba(217,180,91,.3);border-radius:16px;padding:26px 24px;text-align:center">' +
              '<div style="color:#e6c169;font-size:12px;letter-spacing:.22em;text-transform:uppercase;font-weight:700">Password reset</div>' +
              '<p style="color:#c8c2b0;line-height:1.6;font-size:14px">Assalamu alaikum, use this code to reset your Sirat Khushu password:</p>' +
              '<div style="font-size:34px;font-weight:800;letter-spacing:.3em;color:#f4ecd8;margin:14px 0;padding:14px;background:rgba(217,180,91,.08);border:1px solid rgba(217,180,91,.25);border-radius:12px">' + code + '</div>' +
              '<p style="color:#8a94a6;font-size:12px">It expires in 15 minutes. If you didn&rsquo;t request this, you can safely ignore this email.</p></div>',
          });
        } catch (e) { console.error('[mail] send failed:', e.message); return res.status(502).json({ error: 'could not send the email right now — please try again shortly' }); }
      }
    }
    // Generic response — never reveal whether the email is registered. The app shows the address the user typed.
    res.json({ ok: true, sent: true });
  } catch (e) { console.error('[auth/forgot-email]', e.message); res.status(500).json({ error: 'internal error' }); }
});

// Verify the emailed code and set a new password.
app.post('/auth/reset-email', authLimiter, authGuard, async (req, res) => {
  try {
    const { username, email, code, newPassword } = req.body || {};
    let key = null, u = null;
    if (email) { const f = findByEmail(email); if (f) { key = f.key; u = f.u; } }
    else { key = normUser(username).toLowerCase(); u = has(accounts.users, key) ? accounts.users[key] : null; }
    if (typeof newPassword !== 'string' || newPassword.length < 6) return res.status(400).json({ error: 'password too short (6+ characters)' });
    if (newPassword.length > PW_MAX) return res.status(400).json({ error: 'password too long' });
    if (!u || !u.resetCode) return res.status(400).json({ error: 'request a code first' });
    if (u.resetCode.exp < Date.now()) { delete u.resetCode; saveUser(key); return res.status(400).json({ error: 'that code has expired — request a new one' }); }
    if ((u.resetCode.tries || 0) >= 6) { delete u.resetCode; saveUser(key); return res.status(429).json({ error: 'too many wrong codes — request a new one' }); }
    let ok = false;
    if (typeof code === 'string') { const ch = sha256hex(code.trim()); ok = ch.length === u.resetCode.hash.length && crypto.timingSafeEqual(Buffer.from(ch), Buffer.from(u.resetCode.hash)); }
    if (!ok) {
      u.resetCode.tries = (u.resetCode.tries || 0) + 1;
      const g = u.resetGuard || (u.resetGuard = {});                                                    // PERSISTENT wrong-code counter (survives resetCode deletion)
      if (!g.failStart || (Date.now() - g.failStart) > RESET_FAIL_WINDOW_MS) { g.failStart = Date.now(); g.fails = 0; }
      g.fails = (g.fails || 0) + 1;
      saveUser(key);
      return res.status(401).json({ error: 'that code is not correct' });
    }
    await finishReset(res, key, u, newPassword);
  } catch (e) { console.error('[auth/reset-email]', e.message); res.status(500).json({ error: 'internal error' }); }
});
function maskEmail(e) { const [a, b] = String(e).split('@'); if (!b) return null; return (a.slice(0, 2) + '***@' + b); }

app.post('/auth/login', authLimiter, authGuard, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const key = normUser(username).toLowerCase();
    const u = has(accounts.users, key) ? accounts.users[key] : null;
    // Verify the password FIRST. A correct password is NEVER rejected — so an attacker who knows a
    // username cannot lock the real owner out by spamming wrong guesses. Brute force is bounded by
    // scrypt's cost and the per-IP authLimiter instead of an account-level lock.
    let ok = false;
    if (u && typeof password === 'string' && password && password.length <= PW_MAX) {
      const h = await scryptHex(password, u.salt);
      ok = h.length === u.hash.length && crypto.timingSafeEqual(Buffer.from(h), Buffer.from(u.hash));
    } else if (typeof password === 'string' && password && password.length <= PW_MAX) {
      await scryptHex(password, DUMMY_SALT);   // same cost when the username doesn't exist, so response time can't reveal it
    }
    if (!ok) return res.status(401).json({ error: 'wrong name or password' });
    const token = issueToken(key);
    let data = null; try { data = u.data ? JSON.parse(u.data) : null; } catch (_) { data = null; }
    res.json({ ok: true, token, username: u.username, email: u.email, data, rev: u.rev || 0 });
  } catch (e) { console.error('[auth/login]', e.message); res.status(500).json({ error: 'internal error' }); }
});

app.post('/auth/sync', writeLimiter, authGuard, (req, res) => {
  const a = userFromReq(req);
  if (!a) return res.status(401).json({ error: 'invalid or expired token' });
  const { data, baseRev } = req.body || {};
  if (!data || typeof data !== 'object') return res.status(400).json({ error: 'missing data' });
  const blob = JSON.stringify(data);
  if (Buffer.byteLength(blob) > BLOB_MAX) return res.status(413).json({ error: 'data too large' });
  const cur = a.user.rev || 0;
  // Optimistic concurrency: the client must be editing the version it last saw. If another device
  // advanced the rev in the meantime, reject with the current server copy so the client can
  // reconcile instead of blindly overwriting newer data.
  if (typeof baseRev === 'number' && baseRev !== cur) {
    let curData = null; try { curData = a.user.data ? JSON.parse(a.user.data) : null; } catch (_) {}
    return res.status(409).json({ error: 'conflict', rev: cur, data: curData });
  }
  a.user.data = blob; a.user.rev = cur + 1; a.user.updatedAt = Date.now(); saveUser(a.key);
  res.json({ ok: true, rev: a.user.rev, savedAt: a.user.updatedAt });
});

app.post('/auth/password', authLimiter, authGuard, async (req, res) => {
  try {
    const a = userFromReq(req);
    if (!a) return res.status(401).json({ error: 'invalid or expired token' });
    const { newPassword } = req.body || {};
    if (typeof newPassword !== 'string' || newPassword.length < 6) return res.status(400).json({ error: 'password too short (6+ characters)' });
    if (newPassword.length > PW_MAX) return res.status(400).json({ error: 'password too long' });
    a.user.salt = crypto.randomBytes(16).toString('hex');
    a.user.hash = await scryptHex(newPassword, a.user.salt);
    a.user.updatedAt = Date.now();
    revokeTokens(a.key, a.th);                            // evict every other signed-in device
    saveUser(a.key); saveTokens();
    res.json({ ok: true });
    sendPasswordChangedAlert(a.user, req);                // notify the owner their password changed
  } catch (e) { console.error('[auth/password]', e.message); res.status(500).json({ error: 'internal error' }); }
});

app.post('/auth/logout', (req, res) => {
  const th = tokenHashFromReq(req);
  if (th && has(accounts.tokens, th)) { delete accounts.tokens[th]; saveTokens(); }
  res.json({ ok: true });
});

/* ── 3) PUSH: only meaningful when VAPID keys are set ─────────────────────────── */
function requirePush(req, res) {
  if (!PUSH_ENABLED) { res.status(503).json({ error: 'push disabled — set VAPID keys to enable background reminders' }); return false; }
  return true;
}

// SSRF guard: the subscription endpoint is later POSTed to by web-push. Only allow the real
// browser push services, so a caller can't make the server reach internal/private hosts.
const PUSH_HOSTS = ['.googleapis.com', '.push.services.mozilla.com', '.push.apple.com', '.notify.windows.com', '.wns.windows.com'];
function isAllowedPushEndpoint(ep) {
  let u;
  try { u = new URL(ep); } catch (_) { return false; }
  if (u.protocol !== 'https:') return false;
  const host = u.hostname.toLowerCase();
  return PUSH_HOSTS.some((suf) => host.endsWith(suf));
}

app.get('/vapid', (req, res) => {
  if (!requirePush(req, res)) return;
  res.json({ publicKey: PUBLIC });
});

app.post('/subscribe', writeLimiter, (req, res) => {
  if (!requirePush(req, res)) return;
  if (!guard(req, res)) return;
  const { subscription, schedule } = req.body || {};
  if (!subscription || typeof subscription.endpoint !== 'string' || !isAllowedPushEndpoint(subscription.endpoint)) {
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
  store.saveSub(subscription.endpoint);          // one row, not the whole table
  res.json({ ok: true, queued: clean.length });
});

app.post('/unsubscribe', writeLimiter, (req, res) => {
  if (!guard(req, res)) return;   // match /subscribe — a locked (APP_KEY) server must not allow keyless deletes
  const ep = req.body && (req.body.endpoint || (req.body.subscription && req.body.subscription.endpoint));
  if (ep && subs[ep]) { delete subs[ep]; store.deleteSub(ep); }
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
    const touched = new Set();                 // only these rows get rewritten
    for (const ep of Object.keys(subs)) {
      const rec = subs[ep];
      if (!rec || !Array.isArray(rec.schedule)) continue;
      const due = rec.schedule.filter((s) => !s.fired && s.ts <= now && s.ts > now - 15 * 60000);
      for (const item of due) {
        item.fired = true; touched.add(ep);
        try {
          await webpush.sendNotification(rec.subscription, JSON.stringify({ title: item.title, body: item.body, tag: item.tag }));
        } catch (err) {
          if (err && (err.statusCode === 404 || err.statusCode === 410)) { dead.push(ep); break; }
        }
      }
      const before = rec.schedule.length;
      rec.schedule = rec.schedule.filter((s) => s.ts > now - 60 * 60000); // prune >1h old
      if (rec.schedule.length !== before) touched.add(ep);
    }
    dead.forEach((ep) => { delete subs[ep]; touched.delete(ep); store.deleteSub(ep); });
    for (const ep of touched) store.saveSub(ep);
  } finally { _ticking = false; }
}
app.all('/tick', async (req, res) => { await tick().catch((e) => console.error('[tick]', e.message)); res.json({ ok: true, at: Date.now() }); });
if (PUSH_ENABLED) setInterval(() => tick().catch((e) => console.error('[tick]', e.message)), 60000);

/* ── anonymous, opt-in usage analytics ─────────────────────────────────────────
   These are called ONLY when a user turns tracking on in the app (off by default).
   They accept an anonymous per-device id + device type + country + which surah was
   opened. No name, no account link, no Qur'an text — just counts. Everything is
   aggregated in place (bounded) and pruned; nothing is a per-event log. */
const DAYMS = 86400000;
const trackDay = (now) => { const d = new Date(now); return '' + d.getUTCFullYear() + String(d.getUTCMonth() + 1).padStart(2, '0') + String(d.getUTCDate()).padStart(2, '0'); };
const okId = (s) => typeof s === 'string' && /^[A-Za-z0-9_-]{4,64}$/.test(s);
const okDevice = (s) => (s === 'desktop' || s === 'tablet') ? s : 'phone';
// A country name only ever needs letters (incl. accents), spaces, dots, apostrophes, hyphens.
// Stripping everything else defuses HTML/script injection at the source (the dashboard also
// escapes on render) and removes any dangerous object-key characters (e.g. "__proto__").
const okCountry = (s) => (String(s == null ? '' : s).replace(/[^\p{L} .'-]/gu, '').slice(0, 40)) || 'Unknown';
function trackPruneDays() {
  const keep = new Set(); const now = Date.now();
  for (let i = 0; i < 16; i++) keep.add(trackDay(now - i * DAYMS));
  for (const k of Object.keys(analytics.days)) if (!keep.has(k)) delete analytics.days[k];
}
function trackPruneUsers() {
  const cutoff = Date.now() - 90 * DAYMS;   // forget devices inactive 90+ days (bounds the map)
  for (const id of Object.keys(analytics.users)) if ((analytics.users[id].a || 0) < cutoff) delete analytics.users[id];
}
function markActive(id, now) {
  const u = analytics.users[id]; if (u) u.a = now;
  const d = trackDay(now); (analytics.days[d] || (analytics.days[d] = Object.create(null)))[id] = 1;
}
const trackLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });

app.post('/api/track/signup', trackLimiter, (req, res) => {
  if (!guard(req, res)) return;
  const b = req.body || {}; if (!okId(b.id)) return res.status(400).json({ error: 'bad id' });
  const now = Date.now();
  if (!analytics.users[b.id]) analytics.users[b.id] = { c: now, a: now, d: okDevice(b.device), ct: okCountry(b.country) };
  else analytics.users[b.id].a = now;
  markActive(b.id, now); trackPruneDays(); store.saveAnalytics();
  res.json({ ok: true });
});
app.post('/api/track/active', trackLimiter, (req, res) => {
  if (!guard(req, res)) return;
  const b = req.body || {}; if (!okId(b.id)) return res.status(400).json({ error: 'bad id' });
  markActive(b.id, Date.now()); trackPruneDays(); store.saveAnalytics();
  res.json({ ok: true });
});
app.post('/api/track/read', trackLimiter, (req, res) => {
  if (!guard(req, res)) return;
  const b = req.body || {}; if (!okId(b.id)) return res.status(400).json({ error: 'bad id' });
  const n = parseInt(b.surah, 10); const surah = (n >= 1 && n <= 114) ? n : 0;
  if (surah) analytics.surahs[surah] = (analytics.surahs[surah] || 0) + 1;
  markActive(b.id, Date.now());
  if (Math.random() < 0.02) trackPruneUsers();
  trackPruneDays(); store.saveAnalytics();
  res.json({ ok: true });
});
app.post('/api/track/forget', trackLimiter, (req, res) => {
  if (!guard(req, res)) return;                       // user turned tracking OFF → erase their device
  const b = req.body || {}; if (!okId(b.id)) return res.status(400).json({ error: 'bad id' });
  delete analytics.users[b.id];
  for (const d of Object.keys(analytics.days)) delete analytics.days[d][b.id];
  store.saveAnalytics();
  res.json({ ok: true });
});

/* ── admin portal (/admin) ─────────────────────────────────────────────────────
   A dashboard over everything this server stores: accounts, push subscriptions,
   storage use, health. MUST be mounted before the 404 catch-all below, or its
   routes would never be reached.
   It fails closed: with no ADMIN_KEY in .env it serves setup instructions and
   nothing else. Passwords are never shown — only scrypt hashes exist. */
require('./admin').mountAdmin(app, {
  accounts, saveAccounts, revokeTokens,
  subs, saveSubs: () => store.saveAllSubs(),
  analytics,
  USERS_STORE, STORE,
  PUSH_ENABLED, MAIL_ENABLED,
  storeKind: store.kind, storeDescribe: () => store.describe(),
});

// ── 404 + error handler (never leak internals) ────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'not found' }));
app.use((err, req, res, next) => {
  console.error('[server error]', err && err.message);
  res.status(500).json({ error: 'internal error' });
});

// ── crash safety ───────────────────────────────────────────────────────────────
process.on('uncaughtException', (err) => { console.error('[uncaughtException]', err); alertTelegram('uncaughtException: ' + (err && err.message)); });
process.on('unhandledRejection', (reason) => { console.error('[unhandledRejection]', reason); alertTelegram('unhandledRejection: ' + reason); });

// ── start ──────────────────────────────────────────────────────────────────────
// Load both stores BEFORE opening the port. If the port opened first, a request
// arriving during the load would see an empty account map — and a signup in that
// window would be written over the real data once it landed.
async function startServer() {
  try {
    await store.init();
    Object.assign(subs, await store.loadSubs());
    const raw = await store.loadUsers();
    Object.assign(accounts.users, raw.users || {});
    Object.assign(accounts.tokens, raw.tokens || {});
    const ana = await store.loadAnalytics();
    if (ana) {
      Object.assign(analytics.users, ana.users || {});
      Object.assign(analytics.surahs, ana.surahs || {});
      Object.assign(analytics.days, ana.days || {});
    }
  } catch (e) {
    // A configured database that will not answer is fatal: booting anyway would
    // serve an empty account list and quietly overwrite everyone's data.
    console.error('[store] FATAL — could not load state:', e.message);
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`\nSabr Push + Voice Server on :${PORT}`);
    console.log(`  Voice /tts : ON  (recite works with no extra setup)`);
    console.log(`  Push       : ${PUSH_ENABLED ? 'ON' : 'OFF (set VAPID_PUBLIC + VAPID_PRIVATE to enable)'}`);
    console.log(`  Storage    : ${store.describe()}`);
    if (store.kind === 'file' && process.env.RENDER) {
      console.log('  ⚠ WARNING: file storage on Render — the disk is wiped on every restart and');
      console.log('             ALL ACCOUNTS WILL BE LOST. Set DATABASE_URL (free Postgres works).');
    }
    console.log(`  Accounts loaded  : ${Object.keys(accounts.users).length}`);
    console.log(`  Subscribers loaded: ${Object.keys(subs).length}\n`);
    console.log(`  In the app → Settings → paste this server's URL to enable recite everywhere.\n`);
  });
}

// Flush any debounced write before the host stops us, so the last few seconds of
// activity are not lost on redeploy.
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, async () => {
    try { await store.flushNow(); } catch (_) {}
    process.exit(0);
  });
}

startServer();
