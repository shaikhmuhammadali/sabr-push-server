/* ═══════════════════════════════════════════════════════════════════════════
   Sirat Khushu — Admin portal  (a premium, animated Django-/admin-style dashboard)

   Mounts at /admin. Shows every account on this server with a rich, animated
   per-user deep-dive: prayer completion (per salah + streaks), journal (behind a
   privacy veil), learning & growth (xp, dhikr, bookmarks, duas, adhkar, badges),
   password protection status, devices, and server health. You can open a user's
   detail, view their raw blob, sign them out everywhere, delete them, or export.

   SECURITY — read before deploying:
   • FAILS CLOSED. With no ADMIN_KEY set, /admin refuses to serve anything.
   • Set one strong key:   ADMIN_KEY=<long random string>   in your env.
   • The key is compared with timingSafeEqual, never logged, never sent back.
     The browser gets a random httpOnly session cookie instead.
   • Login is rate limited (10 tries / 15 min / IP).

   PASSWORDS ARE NOT SHOWN — they are NOT stored. Signup runs
   crypto.scrypt(password, per-user salt) and keeps only that one-way hash.
   Nobody (you, me, or a thief who steals the DB) can turn it back into the
   original password. The portal shows *that* a password is set and how it is
   protected — never the password. This is deliberate and non-negotiable.

   PRIVACY — the per-user "data" blob holds that person's private journal
   reflections and prayer history. Counts are shown freely; raw journal text is
   blurred behind a "Privacy veil" you must lift per-entry, and the UI says so.
   ═══════════════════════════════════════════════════════════════════════════ */
'use strict';

const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const fmtBytes = (n) => {
  if (!n) return '0 B';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(2) + ' MB';
};

const PRAYERS = ['fajr', 'dhuhr', 'asr', 'maghrib', 'isha'];

/**
 * @param {import('express').Express} app
 * @param {object} ctx  { accounts, saveAccounts, revokeTokens, subs, saveSubs,
 *                        USERS_STORE, STORE, PUSH_ENABLED, MAIL_ENABLED }
 */
function mountAdmin(app, ctx) {
  const ADMIN_KEY = process.env.ADMIN_KEY || '';
  const sessions = new Map();                       // sid -> expiry (in-memory; restart = re-login)
  const SESSION_TTL = 8 * 3600 * 1000;

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 10,
    standardHeaders: true, legacyHeaders: false,
    message: { error: 'too many attempts — wait 15 minutes' },
  });

  // ── auth helpers ───────────────────────────────────────────────────────────
  function keyMatches(provided) {
    if (!ADMIN_KEY || typeof provided !== 'string' || !provided) return false;
    const a = Buffer.from(provided);
    const b = Buffer.from(ADMIN_KEY);
    return crypto.timingSafeEqual(crypto.createHash('sha256').update(a).digest(),
                                  crypto.createHash('sha256').update(b).digest());
  }
  function newSession() {
    const sid = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    for (const [k, exp] of sessions) if (exp < now) sessions.delete(k);
    sessions.set(sid, now + SESSION_TTL);
    return sid;
  }
  function sidFrom(req) {
    const raw = req.headers.cookie || '';
    const m = raw.match(/(?:^|;\s*)sk_admin=([a-f0-9]{64})/);
    return m ? m[1] : null;
  }
  function authed(req) {
    const sid = sidFrom(req);
    if (!sid) return false;
    const exp = sessions.get(sid);
    if (!exp || exp < Date.now()) { if (sid) sessions.delete(sid); return false; }
    return true;
  }
  function gate(req, res, next) {
    if (!ADMIN_KEY) {
      return res.status(503).type('html').send(page('Admin portal is not enabled', `
        <div class="card warn">
          <h2>Set an admin key first</h2>
          <p>This portal refuses to run without one — an admin page that is open by
             default would expose every account on this server.</p>
          <p>Add this to your server's environment, then restart:</p>
          <pre>ADMIN_KEY=${esc(crypto.randomBytes(24).toString('base64url'))}</pre>
          <p class="dim">(A freshly generated suggestion — use it, or any long random string.)</p>
        </div>`));
    }
    if (!authed(req)) return res.status(401).type('html').send(loginPage());
    next();
  }

  // ── data shaping ───────────────────────────────────────────────────────────
  // Light per-user stats for the table (no private text).
  function statsFor(u) {
    const out = { bytes: 0, prayerDays: 0, prayerLogs: 0, journal: 0, dhikr: 0, bookmarks: 0, streak: 0, parsed: false };
    if (!u || !u.data) return out;
    out.bytes = Buffer.byteLength(u.data);
    try {
      const d = JSON.parse(u.data);
      out.parsed = true;
      if (d && typeof d === 'object') {
        if (d.logs && typeof d.logs === 'object') {
          const days = Object.keys(d.logs);
          out.prayerDays = days.length;
          out.prayerLogs = days.reduce((n, k) => n + (d.logs[k] && typeof d.logs[k] === 'object' ? Object.keys(d.logs[k]).length : 0), 0);
        }
        if (Array.isArray(d.journal)) out.journal = d.journal.length;
        out.dhikr = Number(d.dhikrTotal) || 0;
        if (Array.isArray(d.bookmarks)) out.bookmarks = d.bookmarks.length;
        out.streak = Number(d.streakBest) || 0;   // the app's own best-streak value (same field the per-user detail reads)
      }
    } catch (_) { /* unreadable — byte size only */ }
    return out;
  }

  // Rich, curated per-user detail for the deep-dive panel. Journal text is included
  // (the owner explicitly asked to see it) but the UI keeps it behind a privacy veil.
  function detailFor(key, u) {
    const det = {
      key, username: u.username || key, email: u.email || null,
      createdAt: u.createdAt || null, updatedAt: u.updatedAt || null, rev: u.rev || 0,
      bytes: u.data ? Buffer.byteLength(u.data) : 0,
      devices: Object.keys(ctx.accounts.tokens || {}).filter((th) => ctx.accounts.tokens[th] && ctx.accounts.tokens[th].u === key).length,
      password: {
        set: !!(u.hash && u.salt), algo: 'scrypt', salted: !!u.salt,
        recoveryQ: !!u.secAHash,
        resetPending: !!(u.resetCode && u.resetCode.exp && u.resetCode.exp > Date.now()),
        fails: Number(u.fails) || 0,
      },
      prayer: { days: 0, byName: {}, logged: 0, total: 0, completion: 0, streakBest: 0, recent: [] },
      learning: { xp: 0, level: 1, dhikr: 0, bookmarks: 0, duas: 0, adhkar: 0, achievements: 0 },
      journal: [], name: null, city: null, theme: null, method: null,
    };
    PRAYERS.forEach((p) => { det.prayer.byName[p] = 0; });
    let d = null;
    try { d = u.data ? JSON.parse(u.data) : null; } catch (_) { d = null; }
    if (d && typeof d === 'object') {
      if (d.logs && typeof d.logs === 'object') {
        const days = Object.keys(d.logs);
        det.prayer.days = days.length;
        days.forEach((dk) => {
          const day = d.logs[dk]; if (!day || typeof day !== 'object') return;
          PRAYERS.forEach((p) => { if (day[p]) { det.prayer.byName[p]++; det.prayer.logged++; } });
        });
        det.prayer.total = det.prayer.days * PRAYERS.length;
        det.prayer.completion = det.prayer.total ? Math.round((det.prayer.logged / det.prayer.total) * 100) : 0;
        det.prayer.recent = days.sort().slice(-21).map((dk) => {
          const day = d.logs[dk] || {};
          return { day: dk, count: PRAYERS.filter((p) => day[p]).length };
        });
      }
      det.prayer.streakBest = Number(d.streakBest) || 0;
      det.learning.xp = Number(d.xp) || 0;
      det.learning.level = 1 + Math.floor(det.learning.xp / 100);
      det.learning.dhikr = Number(d.dhikrTotal) || 0;
      det.learning.bookmarks = Array.isArray(d.bookmarks) ? d.bookmarks.length : 0;
      det.learning.duas = Array.isArray(d.duas) ? d.duas.length : 0;
      det.learning.adhkar = Number(d.adhkarCount) || 0;
      det.learning.achievements = Array.isArray(d.achievements) ? d.achievements.length
        : (d.achievements && typeof d.achievements === 'object' ? Object.keys(d.achievements).length : 0);
      if (Array.isArray(d.journal)) {
        det.journal = d.journal.slice(0, 200).map((e) => {
          if (!e || typeof e !== 'object') return { date: null, mood: null, text: String(e || '') };
          return { date: e.ts || e.d || null, mood: e.mood || null, text: String(e.reflect || e.text || e.entry || '') };
        });
      }
      det.name = (d.profile && d.profile.name) || (d.account && d.account.name) || null;
      det.city = (d.loc && (d.loc.city || d.loc.name || d.loc.label)) || null;
      det.theme = d.theme || null;
      det.method = d.method || null;
    }
    return det;
  }

  function subsForEmailless() {
    return Object.keys(ctx.subs || {}).map((endpoint) => {
      const s = ctx.subs[endpoint] || {};
      const sched = Array.isArray(s.schedule) ? s.schedule : [];
      let host = '';
      try { host = new URL(endpoint).host; } catch (_) { host = '—'; }
      return {
        host, endpointTail: endpoint.slice(-12),
        scheduled: sched.length,
        pending: sched.filter((x) => x && !x.fired).length,
        updatedAt: s.updatedAt || null,
      };
    });
  }

  function snapshot() {
    // Precompute per-user device (token) counts in ONE O(T) pass — the old per-user filter scanned the
    // ENTIRE token table for EVERY user (O(users x tokens), quadratic) on this ~10s-polled admin path.
    const tokCount = Object.create(null);
    for (const th of Object.keys(ctx.accounts.tokens || {})) {
      const rec = ctx.accounts.tokens[th];
      if (rec && rec.u) tokCount[rec.u] = (tokCount[rec.u] || 0) + 1;
    }
    const users = Object.keys(ctx.accounts.users).map((key) => {
      const u = ctx.accounts.users[key];
      const st = statsFor(u);
      const tokens = tokCount[key] || 0;
      return {
        key, username: u.username || key, email: u.email || null,
        createdAt: u.createdAt || null, updatedAt: u.updatedAt || null, rev: u.rev || 0,
        devices: tokens, hasRecoveryQ: Boolean(u.secAHash),
        pwProtected: Boolean(u.hash && u.salt), stats: st,
      };
    }).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    const totalBytes = users.reduce((n, u) => n + u.stats.bytes, 0);
    const now = Date.now(), DAY = 86400000, weekAgo = now - 7 * DAY;
    const dayStart = (ms) => { const d = new Date(ms); d.setHours(0, 0, 0, 0); return d.getTime(); };
    const created = users.map((u) => u.createdAt || 0).filter(Boolean);
    const todayStart = dayStart(now);
    // 30-day signups sparkline/area chart (real, from account createdAt timestamps)
    const signups = [];
    for (let i = 29; i >= 0; i--) { const s = todayStart - i * DAY; signups.push({ t: Math.floor(s / 1000), count: created.filter((t) => t >= s && t < s + DAY).length }); }
    // cumulative growth curve
    const growth = [];
    for (let i = 29; i >= 0; i--) { const end = todayStart - i * DAY + DAY; growth.push({ t: Math.floor((todayStart - i * DAY) / 1000), count: created.filter((t) => t < end).length }); }
    return {
      users, subs: subsForEmailless(), signups, growth,
      totals: {
        users: users.length,
        activeToday: users.filter((u) => (u.updatedAt || 0) >= todayStart).length,
        activeWeek: users.filter((u) => (u.updatedAt || 0) > weekAgo).length,
        newToday: created.filter((t) => t >= todayStart).length,
        newWeek: created.filter((t) => t >= weekAgo).length,
        withEmail: users.filter((u) => u.email).length,
        devices: Object.keys(ctx.accounts.tokens || {}).length,
        journal: users.reduce((n, u) => n + u.stats.journal, 0),
        prayerLogs: users.reduce((n, u) => n + u.stats.prayerLogs, 0),
        prayerDays: users.reduce((n, u) => n + u.stats.prayerDays, 0),
        dhikr: users.reduce((n, u) => n + u.stats.dhikr, 0),
        bookmarks: users.reduce((n, u) => n + u.stats.bookmarks, 0),
        bytes: totalBytes,
        subs: Object.keys(ctx.subs || {}).length,
      },
      server: {
        push: Boolean(ctx.PUSH_ENABLED),
        email: typeof ctx.MAIL_ENABLED === 'function' ? Boolean(ctx.MAIL_ENABLED()) : false,
        usersFile: ctx.USERS_STORE, subsFile: ctx.STORE,
        storeKind: ctx.storeKind || 'file',
        storeDesc: (typeof ctx.storeDescribe === 'function' ? ctx.storeDescribe() : (ctx.storeKind || 'file')),
        durable: ctx.storeKind === 'postgres',   // false = ephemeral (accounts wiped on restart/sleep)
        uptimeSec: Math.floor(process.uptime()), node: process.version,
        now: new Date().toISOString(),
        ...vitals(),
      },
      delivery: deliveryHealth(),
      retention: retentionCohorts(users),
      devotion: devotionStats(users),
      alerts: alerts(users),
    };
  }

  /* ── Operations intelligence ────────────────────────────────────────────────────
     Everything below is derived from data the server ACTUALLY holds — process metrics,
     the real push-tick counters, and account timestamps. Nothing is estimated or faked;
     when a source genuinely has no data yet, the panel says so rather than inventing a number. */

  // Live process vitals. Memory matters on the free tier (512 MB) — an OOM restart on FILE
  // storage silently wipes every account, so surfacing headroom is a real safety signal.
  function vitals() {
    let mem = null;
    try {
      const m = process.memoryUsage();
      mem = { rss: m.rss, heapUsed: m.heapUsed, heapTotal: m.heapTotal, limitMB: 512 };
    } catch (_) {}
    return { mem, pid: process.pid, platform: process.platform };
  }

  // Push delivery health from the real tick() counters. Reminders are the one feature that fails
  // silently, so this is the difference between "reminders are broken" being visible or invisible.
  function deliveryHealth() {
    const p = ctx.pushStats;
    if (!p) return { available: false };
    const t = p.total || {};
    const attempted = (t.sent || 0) + (t.failed || 0);
    const subsAll = Object.values(ctx.subs || {});
    let pending = 0, scheduled = 0;
    for (const s of subsAll) {
      const sch = Array.isArray(s && s.schedule) ? s.schedule : [];
      scheduled += sch.length;
      pending += sch.filter((x) => x && !x.fired).length;
    }
    return {
      available: true,
      enabled: Boolean(ctx.PUSH_ENABLED),
      runs: p.runs || 0,
      lastRun: p.lastRun || null,
      lastDurationMs: p.lastDurationMs || 0,
      last: p.last || {},
      total: t,
      // successRate is null (not 0) until something has actually been attempted — never imply failure from no data
      successRate: attempted ? Math.round(((t.sent || 0) / attempted) * 1000) / 10 : null,
      recent: p.recent || [],
      subscriptions: subsAll.length,
      scheduled, pending,
    };
  }

  // Weekly retention: of the accounts created in week N, how many are still syncing (updatedAt)?
  // Real signal for whether the app keeps people, computed purely from timestamps we already store.
  function retentionCohorts(users) {
    const now = Date.now(), WEEK = 7 * 86400000;
    const out = [];
    for (let w = 5; w >= 0; w--) {
      const start = now - (w + 1) * WEEK, end = now - w * WEEK;
      const cohort = users.filter((u) => (u.createdAt || 0) >= start && (u.createdAt || 0) < end);
      const active = cohort.filter((u) => (u.updatedAt || 0) > now - 2 * WEEK).length;
      out.push({
        weeksAgo: w, size: cohort.length, retained: active,
        pct: cohort.length ? Math.round((active / cohort.length) * 100) : null,
      });
    }
    return out;
  }

  // What the app is actually FOR. Prayer completion = logged prayers vs the 5-a-day opportunity
  // across the days each user has tracked — the truest measure of whether the app is helping.
  function devotionStats(users) {
    const days = users.reduce((n, u) => n + (u.stats.prayerDays || 0), 0);
    const logs = users.reduce((n, u) => n + (u.stats.prayerLogs || 0), 0);
    const streaks = users.map((u) => u.stats.streak || 0).filter((n) => n > 0);
    return {
      prayerDays: days, prayerLogs: logs,
      completion: days ? Math.round((logs / (days * 5)) * 1000) / 10 : null,   // null = nothing tracked yet
      bestStreak: streaks.length ? Math.max(...streaks) : 0,
      avgStreak: streaks.length ? Math.round((streaks.reduce((a, b) => a + b, 0) / streaks.length) * 10) / 10 : 0,
      engaged: users.filter((u) => (u.stats.prayerLogs || 0) > 0).length,
    };
  }

  // Actionable warnings, worst first. Each one is a real condition with a real consequence —
  // no cosmetic "all good" noise, and every item tells the owner what to DO about it.
  function alerts(users) {
    const out = [];
    const durable = ctx.storeKind === 'postgres';
    if (!durable) out.push({ level: 'critical', title: 'Storage is not durable', body: 'Accounts live on an ephemeral disk and are WIPED on every restart, redeploy or sleep. Set DATABASE_URL to a Postgres connection string.' });
    if (!ctx.PUSH_ENABLED) out.push({ level: 'warn', title: 'Push is disabled', body: 'No prayer reminders can be delivered. Set the VAPID keys to enable background reminders.' });
    if (typeof ctx.MAIL_ENABLED === 'function' && !ctx.MAIL_ENABLED()) out.push({ level: 'warn', title: 'Email is disabled', body: 'Password reset by email cannot work. Set RESEND_API_KEY or BREVO_API_KEY + MAIL_FROM.' });
    const p = ctx.pushStats;
    if (p && p.total && (p.total.sent + p.total.failed) > 20) {
      const rate = p.total.sent / (p.total.sent + p.total.failed);
      if (rate < 0.9) out.push({ level: 'warn', title: 'Push delivery is degraded', body: Math.round(rate * 100) + '% of reminder sends are succeeding. Check the push service and prune dead endpoints.' });
    }
    if (ctx.MAX_ACCOUNTS && users.length >= ctx.MAX_ACCOUNTS * 0.8) {
      out.push({ level: 'warn', title: 'Approaching the signup ceiling', body: users.length + ' of ' + ctx.MAX_ACCOUNTS + ' accounts used. New signups are refused at the cap.' });
    }
    const noEmail = users.filter((u) => !u.email).length;
    if (users.length && noEmail / users.length > 0.5) out.push({ level: 'info', title: 'Most accounts have no email', body: noEmail + ' of ' + users.length + ' accounts cannot recover a forgotten password.' });
    return out;
  }

  // ── routes ─────────────────────────────────────────────────────────────────
  app.post('/admin/login', loginLimiter, (req, res) => {
    const key = (req.body && req.body.key) || '';
    if (!ADMIN_KEY) return res.status(503).json({ error: 'ADMIN_KEY is not set on the server' });
    if (!keyMatches(key)) return res.status(401).json({ error: 'wrong key' });
    const sid = newSession();
    const secure = (process.env.NODE_ENV === 'production' || req.secure) ? ' Secure;' : '';
    res.set('Set-Cookie', `sk_admin=${sid}; HttpOnly; SameSite=Strict; Path=/admin;${secure} Max-Age=${SESSION_TTL / 1000}`);
    res.json({ ok: true });
  });

  app.post('/admin/logout', (req, res) => {
    const sid = sidFrom(req); if (sid) sessions.delete(sid);
    res.set('Set-Cookie', 'sk_admin=; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=0');
    res.json({ ok: true });
  });

  app.get('/admin', gate, (req, res) => res.type('html').send(dashboardPage()));
  app.get('/admin/api/snapshot', gate, (req, res) => res.json(snapshot()));

  // Live email diagnostic: sends a REAL test email through the active transport and returns the exact
  // provider result — so a "reset email not arriving" problem is finally visible. Admin-gated.
  //   curl -X POST .../admin/api/mail-diag -H 'Content-Type: application/json' \
  //        -H 'Cookie: <admin session>' --data '{"to":"you@example.com"}'
  app.post('/admin/api/mail-diag', gate, async (req, res) => {
    const provider = (typeof ctx.mailProvider === 'function' ? ctx.mailProvider() : 'unknown');
    const from = (typeof ctx.mailFrom === 'function' ? ctx.mailFrom() : null);
    const to = String((req.body && req.body.to) || from || '').trim();
    if (!to) return res.status(400).json({ ok: false, provider, from, error: 'pass {"to":"you@example.com"}' });
    if (typeof ctx.sendMailRaw !== 'function') return res.status(500).json({ ok: false, provider, from, error: 'mail transport not wired' });
    try {
      await ctx.sendMailRaw({ to, subject: 'Sirat Khushu — email delivery test',
        text: 'This is a test from the admin mail diagnostic. If you received it, password-reset emails will arrive too.',
        html: '<p>This is a <b>test</b> from the admin mail diagnostic. If you received it, password-reset emails will arrive too. ✅</p>' });
      res.json({ ok: true, provider, from, to, note: 'Provider ACCEPTED the send. Check the inbox AND spam. Final delivery status is in your provider dashboard.' });
    } catch (e) {
      res.status(502).json({ ok: false, provider, from, to, error: String((e && e.message) || e).slice(0, 400) });
    }
  });

  // Curated deep-dive for ONE user (prayer/journal/learning/password status).
  app.get('/admin/api/user/:key/detail', gate, (req, res) => {
    const key = String(req.params.key).toLowerCase();
    const u = ctx.accounts.users[key];
    if (!u) return res.status(404).json({ error: 'no such user' });
    res.json(detailFor(key, u));
  });

  // Raw blob for ONE user — deliberately a separate, explicit call.
  app.get('/admin/api/user/:key/raw', gate, (req, res) => {
    const u = ctx.accounts.users[String(req.params.key).toLowerCase()];
    if (!u) return res.status(404).json({ error: 'no such user' });
    let parsed = null;
    try { parsed = u.data ? JSON.parse(u.data) : null; } catch (_) { parsed = null; }
    res.json({ username: u.username, bytes: u.data ? Buffer.byteLength(u.data) : 0, data: parsed });
  });

  // Full export (accounts + subs). Password/recovery hashes stripped.
  app.get('/admin/api/export', gate, (req, res) => {
    const users = {};
    for (const k of Object.keys(ctx.accounts.users)) {
      const u = ctx.accounts.users[k];
      users[k] = { ...u };
      delete users[k].hash; delete users[k].salt;
      delete users[k].secAHash; delete users[k].secASalt;
      delete users[k].resetCode;
    }
    res.set('Content-Disposition', 'attachment; filename="sirat-khushu-export.json"');
    res.json({ exportedAt: new Date().toISOString(), note: 'password/recovery hashes intentionally omitted', users, subs: ctx.subs });
  });

  app.post('/admin/api/user/:key/signout', gate, (req, res) => {
    const key = String(req.params.key).toLowerCase();
    if (!ctx.accounts.users[key]) return res.status(404).json({ error: 'no such user' });
    if (typeof ctx.revokeTokens === 'function') ctx.revokeTokens(key, null);
    else {
      for (const th of Object.keys(ctx.accounts.tokens)) if (ctx.accounts.tokens[th].u === key) delete ctx.accounts.tokens[th];
    }
    // Always persist. revokeTokens() only mutates the in-memory token table; without this save the
    // eviction is lost on the next restart (on Postgres a normal /auth/sync never rewrites the tokens
    // row), so a "signed-out-everywhere" session silently resurrects. Matches the delete handler below.
    ctx.saveAccounts();
    res.json({ ok: true });
  });

  app.post('/admin/api/user/:key/delete', gate, (req, res) => {
    const key = String(req.params.key).toLowerCase();
    if (!ctx.accounts.users[key]) return res.status(404).json({ error: 'no such user' });
    if (String((req.body && req.body.confirm) || '').toLowerCase() !== key) {
      return res.status(400).json({ error: 'type the username to confirm' });
    }
    delete ctx.accounts.users[key];
    for (const th of Object.keys(ctx.accounts.tokens)) if (ctx.accounts.tokens[th].u === key) delete ctx.accounts.tokens[th];
    ctx.saveAccounts();
    res.json({ ok: true });
  });

  try { require('./admin-analytics').mount(app, gate, ctx); }
  catch (e) { console.error('[admin] analytics mount failed:', e.message); }

  console.log('[admin] portal mounted at /admin ' + (ADMIN_KEY ? '(key set)' : '— DISABLED: set ADMIN_KEY to enable'));
}

/* ── views ─────────────────────────────────────────────────────────────────── */
const CSS = `
:root{--bg:#070a11;--bg2:#0e1420;--bg3:#0b1018;--panel:#111a2b;--panel2:#0d1422;--line:#1f2a3d;--line2:#2b3a54;
  --text:#eaeef9;--dim:#8794b0;--gold:#e6c169;--gold2:#d9b45b;--goldink:#f3dd9e;
  --green:#4ec98b;--red:#e2685f;--blue:#6aa8ff;--violet:#a98bff;--teal:#5ad3c6}
@property --p{syntax:'<number>';inherits:false;initial-value:0}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;min-height:100vh;color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;-webkit-font-smoothing:antialiased;
  background:radial-gradient(1100px 620px at 78% -12%,rgba(30,44,80,.55),transparent 62%),radial-gradient(820px 560px at -8% 8%,rgba(40,26,74,.42),transparent 58%),radial-gradient(760px 720px at 118% 116%,rgba(20,60,58,.22),transparent 60%),var(--bg)}
a{color:var(--gold);text-decoration:none}
code,pre{font-family:ui-monospace,Consolas,monospace}
pre{background:#080c14;border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;font-size:13px}
.dim{color:var(--dim)}.right{text-align:right}.mono{font-variant-numeric:tabular-nums}
/* ── shell ── */
.shell{display:grid;grid-template-columns:236px 1fr;min-height:100vh}
.side{position:sticky;top:0;align-self:start;height:100vh;display:flex;flex-direction:column;gap:4px;padding:22px 16px;border-right:1px solid var(--line);background:linear-gradient(180deg,rgba(255,255,255,.02),transparent),rgba(10,14,22,.5);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px)}
.side .brand{display:flex;align-items:center;gap:12px;padding:4px 8px 18px}
.logo{width:44px;height:44px;border-radius:13px;display:grid;place-items:center;font-size:22px;flex:none;background:linear-gradient(145deg,#1c2740,#0e1424);border:1px solid var(--line2);box-shadow:0 6px 22px rgba(0,0,0,.45),inset 0 1px 0 rgba(255,255,255,.06);animation:floaty 5s ease-in-out infinite}
@keyframes floaty{50%{transform:translateY(-4px)}}
.brand .bt{font-size:1rem;font-weight:800;letter-spacing:.02em;line-height:1.1;background:linear-gradient(90deg,#fff,var(--gold));-webkit-background-clip:text;background-clip:text;color:transparent}
.brand .bs{display:block;font-size:.63rem;color:var(--dim);letter-spacing:.16em;text-transform:uppercase;margin-top:3px}
.nav{display:flex;flex-direction:column;gap:2px;margin-top:4px}
.nav a{display:flex;align-items:center;gap:11px;padding:10px 12px;border-radius:11px;color:var(--dim);font-size:.9rem;font-weight:600;border:1px solid transparent;transition:.18s}
.nav a .ni{width:18px;text-align:center;font-size:1rem;opacity:.92}
.nav a:hover{color:var(--text);background:rgba(255,255,255,.03)}
.nav a.on{color:var(--goldink);background:linear-gradient(90deg,rgba(230,193,105,.14),transparent);border-color:var(--line);box-shadow:inset 2px 0 0 var(--gold)}
.side .sgrow{flex:1}
.side .foot{border-top:1px solid var(--line);padding-top:12px;display:flex;flex-direction:column;gap:6px}
.main{min-width:0;padding:26px 30px 80px;max-width:1200px}
@media(max-width:900px){.shell{grid-template-columns:1fr}.side{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;border-right:0;border-bottom:1px solid var(--line);gap:6px}.side .brand{padding:4px 8px}.nav{flex-direction:row;flex-wrap:wrap;margin:0}.side .sgrow{display:none}.side .foot{border-top:0;flex-direction:row;padding-top:0}.main{padding:20px 16px 60px}}
/* ── topbar ── */
.topbar{display:flex;align-items:flex-end;justify-content:space-between;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.topbar h1{font-size:1.55rem;margin:0;letter-spacing:.01em;font-weight:800}
.topbar .sub{color:var(--dim);font-size:.82rem;margin-top:4px}
.tbtools{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
/* ── buttons / pills / toggle ── */
.btn{background:#131c2d;border:1px solid var(--line);color:var(--text);border-radius:10px;padding:8px 13px;font-size:13px;cursor:pointer;transition:.2s;text-decoration:none;display:inline-flex;align-items:center;gap:7px;white-space:nowrap}
.btn:hover{border-color:var(--gold);transform:translateY(-1px)}
.btn.gold{background:linear-gradient(145deg,var(--gold),#c99f43);color:#0a0d14;border-color:transparent;font-weight:800}
.btn.danger{border-color:#5a2a26;color:#ffb3ad}.btn.danger:hover{border-color:var(--red)}
.pill{display:inline-flex;align-items:center;gap:5px;padding:4px 11px;border-radius:999px;font-size:.72rem;border:1px solid var(--line);color:var(--dim)}
.pill.ok{color:var(--green);border-color:#245c42;background:rgba(78,201,139,.08)}
.pill.off{color:var(--red);border-color:#5a2a26}
.pill.warnp{color:var(--gold);border-color:#5a4a1e;background:rgba(230,193,105,.08)}
.toggle{display:inline-flex;align-items:center;gap:7px;font-size:.74rem;color:var(--dim);cursor:pointer;user-select:none}
.sw{width:34px;height:19px;border-radius:99px;background:#1c2740;border:1px solid var(--line);position:relative;transition:.25s}
.sw::after{content:'';position:absolute;top:1px;left:1px;width:15px;height:15px;border-radius:50%;background:var(--dim);transition:.25s}
.toggle.on .sw{background:rgba(230,193,105,.25);border-color:var(--gold)}.toggle.on .sw::after{left:16px;background:var(--gold)}
/* ── section / card ── */
.section{margin-bottom:24px;scroll-margin-top:18px}
.card{background:linear-gradient(180deg,rgba(255,255,255,.02),transparent),var(--panel);border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:0 14px 40px -18px rgba(0,0,0,.6);opacity:0;transform:translateY(14px);animation:rise .6s cubic-bezier(.2,.7,.2,1) forwards}
.card.warn{border-color:#5a4a1e;background:#1a1710}
@keyframes rise{to{opacity:1;transform:none}}
h2.sh{font-size:.72rem;letter-spacing:.2em;text-transform:uppercase;color:var(--gold);margin:0 0 16px;display:flex;align-items:center;gap:9px}
h2.sh::before{content:'';width:16px;height:2px;border-radius:2px;background:linear-gradient(90deg,var(--gold),transparent)}
h2.sh .c{margin-left:auto;color:var(--dim);letter-spacing:.04em;font-size:.9em;text-transform:none}
/* ── hero KPIs ── */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(184px,1fr));gap:14px;margin-bottom:22px}
.kpi{position:relative;overflow:hidden;border-radius:18px;padding:18px 18px 16px;border:1px solid var(--line);background:linear-gradient(165deg,rgba(22,32,52,.55),#0d1524),var(--panel2);transition:transform .28s,border-color .28s,box-shadow .28s;opacity:0;transform:translateY(16px);animation:rise .55s cubic-bezier(.2,.7,.2,1) forwards}
.kpi:hover{transform:translateY(-4px);border-color:var(--line2);box-shadow:0 20px 40px -22px rgba(0,0,0,.85)}
.kpi::before{content:'';position:absolute;inset:0 0 auto 0;height:3px;background:linear-gradient(90deg,var(--acc,var(--gold)),transparent 82%)}
.kpi .ico{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;font-size:1.15rem;margin-bottom:12px;background:radial-gradient(circle at 38% 32%,color-mix(in srgb,var(--acc,var(--gold)) 32%,transparent),transparent 72%);border:1px solid var(--line)}
.kpi .v{font-size:2rem;font-weight:800;font-variant-numeric:tabular-nums;letter-spacing:-.02em;line-height:1}
.kpi .l{color:var(--dim);font-size:.72rem;text-transform:uppercase;letter-spacing:.09em;margin-top:5px;font-weight:600}
.kpi .t{font-size:.72rem;margin-top:9px;color:var(--green);display:flex;align-items:center;gap:5px}
.kpi .t.flat{color:var(--dim)}
/* ── alerts ── */
.alert{display:flex;gap:13px;align-items:flex-start;padding:14px 16px;border-radius:14px;margin-bottom:11px;border:1px solid var(--line);background:var(--panel2);
  opacity:0;transform:translateY(-8px);animation:rise .5s cubic-bezier(.2,.7,.2,1) forwards}
.alert .ai{font-size:1.1rem;line-height:1.3;flex:none}
.alert b{display:block;font-size:.93rem;margin-bottom:3px}
.alert p{margin:0;color:var(--dim);font-size:.83rem;line-height:1.55}
.alert.critical{border-color:#6b2733;background:linear-gradient(180deg,rgba(214,73,97,.13),transparent),var(--panel2)}
.alert.critical b{color:#ff8a9e}
.alert.critical .ai{animation:pulseA 1.9s ease-in-out infinite}
.alert.warn{border-color:#5a4a1e;background:linear-gradient(180deg,rgba(230,193,105,.10),transparent),var(--panel2)}
.alert.warn b{color:var(--gold)}
.alert.info{border-color:var(--line2)}
@keyframes pulseA{50%{transform:scale(1.16);opacity:.75}}
/* ── gauge + meters ── */
.opsgrid{display:grid;grid-template-columns:auto 1fr;gap:22px;align-items:center}
@media(max-width:720px){.opsgrid{grid-template-columns:1fr}}
.gauge{position:relative;width:132px;height:132px;flex:none}
.gauge svg{transform:rotate(-90deg)}
.gauge .gv{position:absolute;inset:0;display:grid;place-items:center;text-align:center}
.gauge .gv b{font-size:1.5rem;font-weight:800;font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.gauge .gv span{display:block;font-size:.6rem;color:var(--dim);text-transform:uppercase;letter-spacing:.1em;margin-top:2px}
.gring{stroke-dasharray:339.3;stroke-dashoffset:339.3;transition:stroke-dashoffset 1.1s cubic-bezier(.2,.7,.2,1)}
.mrow{display:grid;grid-template-columns:118px 1fr auto;gap:12px;align-items:center;margin-bottom:11px;font-size:.83rem}
.mrow .ml{color:var(--dim)}
.mbar{height:8px;border-radius:99px;background:#0c1320;border:1px solid var(--line);overflow:hidden}
.mbar i{display:block;height:100%;width:0;border-radius:99px;background:linear-gradient(90deg,var(--gold2),var(--gold));transition:width 1s cubic-bezier(.2,.7,.2,1)}
.mbar i.g{background:linear-gradient(90deg,#2f9e6b,#48d39a)}
.mbar i.r{background:linear-gradient(90deg,#a33b4e,#e0687f)}
.mrow .mv{font-variant-numeric:tabular-nums;font-weight:700;min-width:66px;text-align:right}
.statline{display:flex;flex-wrap:wrap;gap:10px;margin-top:16px}
.stat{flex:1 1 118px;background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:11px 13px}
.stat b{display:block;font-size:1.22rem;font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.stat span{font-size:.68rem;color:var(--dim);text-transform:uppercase;letter-spacing:.08em}
/* ── cohort heatmap ── */
.cohorts{display:flex;gap:9px;flex-wrap:wrap}
.coh{flex:1 1 92px;border-radius:13px;border:1px solid var(--line);padding:13px 12px;text-align:center;background:var(--panel2);
  opacity:0;transform:scale(.94);animation:pop .5s cubic-bezier(.2,.7,.2,1) forwards}
@keyframes pop{to{opacity:1;transform:none}}
.coh .cp{font-size:1.32rem;font-weight:800;font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.coh .cw{font-size:.66rem;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-top:5px}
.coh .cn{font-size:.7rem;color:var(--dim);margin-top:3px}
/* ── chart ── */
.chart svg{display:block;width:100%}.chart svg text{fill:var(--dim);font-size:10px}
/* ── tables ── */
table{width:100%;border-collapse:collapse;font-size:14px}.tblwrap{overflow-x:auto;border-radius:12px}
th,td{text-align:left;padding:12px 11px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--dim);font-size:.68rem;letter-spacing:.11em;text-transform:uppercase;font-weight:600}
tr.urow{cursor:pointer;transition:background .18s}tr.urow:hover{background:rgba(230,193,105,.05)}
tr.urow.open{background:rgba(230,193,105,.07)}
tr:last-child td{border-bottom:0}
.av{width:36px;height:36px;border-radius:11px;display:inline-grid;place-items:center;font-weight:800;color:#0a0d14;background:linear-gradient(145deg,var(--gold),#b98f3e);font-size:.92rem}
.uname{display:flex;align-items:center;gap:11px}.uname b{font-weight:700}
.chev{display:inline-block;transition:transform .3s;color:var(--dim)}tr.urow.open .chev{transform:rotate(90deg);color:var(--gold)}
.acts{display:flex;gap:6px;justify-content:flex-end}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
input[type=password],input[type=text]{background:#080c14;border:1px solid var(--line);color:var(--text);border-radius:10px;padding:12px 14px;font-size:15px;width:100%}
/* ── login ── */
.login{max-width:400px;margin:13vh auto;padding:0 18px}
.login .brand{display:flex;justify-content:center;margin-bottom:8px}
h1{font-size:1.28rem;margin:0;letter-spacing:.02em}
h1.center{text-align:center;background:linear-gradient(90deg,#fff,var(--gold));-webkit-background-clip:text;background-clip:text;color:transparent}
h1 small{color:var(--dim);font-weight:400;font-size:.76rem;display:block;margin-top:2px;-webkit-text-fill-color:var(--dim)}
h2{font-size:.76rem;letter-spacing:.2em;text-transform:uppercase;color:var(--gold);margin:0 0 15px}
.note{background:linear-gradient(90deg,rgba(230,193,105,.08),transparent);border-left:3px solid var(--gold);padding:12px 15px;border-radius:0 10px 10px 0;color:#cdbd94;font-size:13.5px;margin-bottom:18px}
.err{color:#ffb3ad;font-size:13.5px;min-height:19px;margin-top:9px}
/* ── deep-dive detail ── */
.detail td{padding:0;border-bottom:1px solid var(--line)}
.dwrap{overflow:hidden;max-height:0;transition:max-height .5s cubic-bezier(.2,.7,.2,1)}
tr.detail.open .dwrap{max-height:1600px}
.dinner{padding:20px 6px;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
.panel{background:linear-gradient(180deg,#0f1524,#0a0e1a);border:1px solid var(--line);border-radius:14px;padding:16px 17px;opacity:0;transform:translateY(10px)}
tr.detail.open .panel{animation:rise .5s ease forwards}
tr.detail.open .panel:nth-child(2){animation-delay:.06s}tr.detail.open .panel:nth-child(3){animation-delay:.12s}tr.detail.open .panel:nth-child(4){animation-delay:.18s}
.ptitle{font-size:.7rem;letter-spacing:.14em;text-transform:uppercase;color:var(--dim);margin:0 0 12px;display:flex;align-items:center;gap:7px}
.ringwrap{display:flex;align-items:center;gap:16px}
.ring{--p:0;width:104px;height:104px;flex:0 0 auto;border-radius:50%;display:grid;place-items:center;position:relative;background:conic-gradient(var(--gold) calc(var(--p)*1%),#1a2233 0);transition:--p 1.1s cubic-bezier(.2,.7,.2,1)}
.ring::before{content:'';position:absolute;width:78px;height:78px;border-radius:50%;background:var(--bg3);box-shadow:inset 0 2px 8px rgba(0,0,0,.5)}
.ring b{position:relative;font-size:1.35rem;font-weight:800;font-variant-numeric:tabular-nums}
.ring i{position:relative;display:block;font-size:.6rem;letter-spacing:.1em;color:var(--dim);font-style:normal;text-align:center}
.bars{flex:1;display:flex;flex-direction:column;gap:7px;min-width:120px}
.bar{display:grid;grid-template-columns:74px 1fr 34px;align-items:center;gap:8px;font-size:.78rem}
.bar .tk{height:8px;border-radius:5px;background:#161d2e;overflow:hidden}
.bar .tk i{display:block;height:100%;width:0;border-radius:5px;background:linear-gradient(90deg,var(--gold2),var(--gold));transition:width 1s cubic-bezier(.2,.7,.2,1)}
.bar .vv{text-align:right;color:var(--dim);font-variant-numeric:tabular-nums}
.heat{display:flex;gap:3px;margin-top:14px;flex-wrap:wrap}
.heat i{width:13px;height:13px;border-radius:3px;background:#141b2c;border:1px solid #1c2740}
.heat i.c1{background:#2a3a24}.heat i.c2{background:#3d5c2f}.heat i.c3{background:#4e7a3a}.heat i.c4{background:#5f9a45}.heat i.c5{background:var(--green)}
.chips{display:grid;grid-template-columns:1fr 1fr;gap:9px}
.chip{background:#0e1526;border:1px solid var(--line);border-radius:11px;padding:11px 12px}
.chip b{display:block;font-size:1.25rem;font-weight:800;font-variant-numeric:tabular-nums}
.chip span{font-size:.68rem;color:var(--dim);text-transform:uppercase;letter-spacing:.06em}
.chip .em{font-size:.95rem;margin-right:5px}
.xpbar{height:7px;border-radius:5px;background:#161d2e;margin-top:9px;overflow:hidden}
.xpbar i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--violet),var(--blue));transition:width 1.1s ease}
.kv{display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-bottom:1px dashed #1c2436;font-size:.86rem}
.kv:last-child{border-bottom:0}.kv span{color:var(--dim)}
.jitem{border:1px solid var(--line);border-radius:11px;padding:11px 13px;margin-bottom:9px;background:#0d1320}
.jhead{display:flex;justify-content:space-between;align-items:center;gap:8px;font-size:.78rem;color:var(--dim);margin-bottom:7px}
.jtext{font-size:.9rem;line-height:1.5;transition:filter .35s;color:#dfe4f2}
.veiled .jtext{filter:blur(6px);user-select:none}
.reveal{font-size:.68rem;color:var(--gold);cursor:pointer;border:1px solid var(--line);border-radius:7px;padding:2px 8px;background:transparent}
.mood{font-size:1rem}
.empty{color:var(--dim);font-size:.86rem;padding:8px 0;font-style:italic}
@media(max-width:560px){.dinner{grid-template-columns:1fr}.ring{width:92px;height:92px}.acts{justify-content:flex-start}}
@media (prefers-reduced-motion:reduce){*{animation-duration:.001s!important;transition-duration:.001s!important}}
`;

function page(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${esc(title)} — Sirat Khushu</title><style>${CSS}</style></head>
<body><div class="wrap">${body}</div></body></html>`;
}

function loginPage() {
  return page('Admin', `
  <div class="login">
    <div class="brand" style="justify-content:center;margin-bottom:8px"><div class="logo">🌙</div></div>
    <h1 class="center">Sirat Khushu <small>admin portal</small></h1>
    <div class="card" style="margin-top:16px">
      <h2>Sign in</h2>
      <input id="k" type="password" placeholder="Admin key" autofocus autocomplete="current-password">
      <div class="err" id="e"></div>
      <div style="margin-top:12px"><button class="btn gold" id="go" style="width:100%;padding:12px">Unlock</button></div>
    </div>
    <p class="dim" style="font-size:12.5px;text-align:center">This is the key from <code>ADMIN_KEY</code> in your server's environment — not any user's password.</p>
  </div>
  <script>
    var k=document.getElementById('k'),e=document.getElementById('e'),go=document.getElementById('go');
    async function submit(){
      e.textContent='';go.disabled=true;
      try{
        var r=await fetch('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:k.value})});
        if(r.ok){location.href='/admin';return;}
        var j=await r.json().catch(function(){return {}});
        e.textContent=j.error==='wrong key'?'That key is not right.':(j.error||'Could not sign in.');
      }catch(err){e.textContent='Network error.';}
      go.disabled=false;
    }
    go.onclick=submit; k.onkeydown=function(ev){if(ev.key==='Enter')submit();};
  </script>`);
}

function dashboardPage() {
  return page('Admin', `
  <div class="shell">
    <aside class="side">
      <div class="brand"><div class="logo">🌙</div><div><span class="bt">Sirat Khushu</span><span class="bs">Admin portal</span></div></div>
      <nav class="nav" id="nav">
        <a href="#s-overview" class="on"><span class="ni">◈</span> Overview</a>
        <a href="#s-delivery"><span class="ni">📡</span> Delivery</a>
        <a href="#s-devotion"><span class="ni">🕌</span> Devotion</a>
        <a href="#s-retention"><span class="ni">📈</span> Retention</a>
        <a href="#s-accounts"><span class="ni">👤</span> Accounts</a>
        <a href="#s-subs"><span class="ni">🔔</span> Subscriptions</a>
        <a href="#s-server"><span class="ni">🖥️</span> Server</a>
      </nav>
      <div class="sgrow"></div>
      <div class="foot">
        <a class="btn" href="/admin/analytics"><span>📊</span> Analytics</a>
        <a class="btn" href="/admin/api/export"><span>⭳</span> Export JSON</a>
        <button class="btn" onclick="logout()"><span>⏻</span> Log out</button>
      </div>
    </aside>

    <main class="main">
      <div class="topbar">
        <div><h1>Overview</h1><div class="sub">Every account on this server · live records</div></div>
        <div class="tbtools">
          <label class="toggle" id="veilT" onclick="toggleVeil()"><span class="sw"></span> Privacy veil</label>
          <span class="pill" id="updated">—</span>
          <button class="btn" onclick="load(true)">↻ Refresh</button>
        </div>
      </div>

      <div class="note">
        <b>Passwords are never shown — they are not stored.</b> Sign-up runs
        <code>scrypt(password, per-user salt)</code> and keeps only that one-way hash, so nobody — you
        included — can reverse it. Journal reflections are personal; keep the <b>Privacy veil</b> on unless you
        have a real reason to read them. Click any account row to open its full detail.
      </div>

      <div id="alerts"></div>

      <section class="section" id="s-overview">
        <div class="kpis" id="kpis"></div>
        <div class="card chartcard"><h2 class="sh">New signups <span class="c">last 30 days · real</span></h2><div class="chart" id="signupsChart"></div></div>
      </section>

      <section class="section" id="s-delivery">
        <div class="card"><h2 class="sh">Reminder delivery <span class="c">live from the scheduler · real</span></h2><div id="delivery"></div></div>
      </section>

      <section class="section" id="s-devotion">
        <div class="card"><h2 class="sh">Devotion <span class="c">what the app is actually for</span></h2><div id="devotion"></div></div>
      </section>

      <section class="section" id="s-retention">
        <div class="card"><h2 class="sh">Weekly retention <span class="c">signup cohorts · still syncing</span></h2><div id="retention"></div></div>
      </section>

      <section class="section" id="s-accounts">
        <div class="card"><h2 class="sh">Accounts <span class="c" id="accCount"></span></h2><div class="tblwrap"><table id="users"></table></div></div>
      </section>

      <section class="section" id="s-subs">
        <div class="card"><h2 class="sh">Push subscriptions</h2><div class="tblwrap"><table id="subs"></table></div></div>
      </section>

      <section class="section" id="s-server">
        <div class="card"><h2 class="sh">Server health</h2><div id="server" class="dim" style="font-size:13.5px"></div></div>
      </section>
    </main>
  </div>

<script>
var D=null, VEIL=true, DET={}, OPEN={};
var PRAYERS=['fajr','dhuhr','asr','maghrib','isha'];
var PMETA={fajr:['Fajr','🌅'],dhuhr:['Dhuhr','☀️'],asr:['Asr','🌤️'],maghrib:['Maghrib','🌇'],isha:['Isha','🌙']};
function h(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function when(t){ if(!t) return '<span class="dim">—</span>'; var d=new Date(t);
  return d.toLocaleDateString(undefined,{day:'numeric',month:'short',year:'numeric'})+' <span class="dim">'+d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'})+'</span>'; }
function ago(t){ if(!t) return '—'; var s=(Date.now()-t)/1000; if(s<3600) return Math.max(1,Math.floor(s/60))+'m ago'; if(s<86400) return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago'; }
function bytes(n){ if(!n) return '0 B'; if(n<1024) return n+' B'; if(n<1048576) return (n/1024).toFixed(1)+' KB'; return (n/1048576).toFixed(2)+' MB'; }
function init(s){ s=String(s||'?').trim(); return (s[0]||'?').toUpperCase(); }
function countUp(el,to){ to=Number(to)||0; var dur=820,t0=null; function step(ts){ if(!t0)t0=ts; var p=Math.min(1,(ts-t0)/dur); el.textContent=Math.round(to*(1-Math.pow(1-p,3))).toLocaleString(); if(p<1)requestAnimationFrame(step);} requestAnimationFrame(step); }

var LAST_SIG='';
async function load(force){
  var r; try{ r=await fetch('/admin/api/snapshot'); }catch(e){ return; }
  if(r.status===401){location.reload();return;}
  var nd=await r.json();
  // change-signature: only re-render when something actually changed, so the auto-refresh never
  // flickers the table or interrupts a deep-dive the admin is reading.
  var _d=nd.delivery||{}, _dt=_d.total||{};
  var sig=nd.users.length+'|'+nd.totals.prayerLogs+'|'+nd.totals.journal+'|'+nd.subs.length+'|'+nd.totals.newToday+'|'+(nd.users[0]&&nd.users[0].updatedAt)
    // delivery telemetry moves independently of accounts — include it so the Delivery panel stays LIVE
    +'|'+(_dt.sent||0)+'|'+(_dt.failed||0)+'|'+(_d.pending||0)+'|'+((nd.alerts||[]).length);
  D=nd; if(!force && sig===LAST_SIG){ return; } LAST_SIG=sig; var t=D.totals;
  var K=[
    ['Accounts',t.users,'👤','var(--gold)', (t.newWeek?('+'+t.newWeek+' this week'):'no new this week')],
    ['Active · week',t.activeWeek,'✨','var(--teal)', (t.activeToday||0)+' today'],
    ['New · today',t.newToday,'🌱','var(--green)', (t.newWeek||0)+' this week'],
    ['Prayers logged',t.prayerLogs,'🕌','var(--blue)', (t.prayerDays||0)+' prayer-days'],
    ['Journal entries',t.journal,'📓','var(--violet)', (t.dhikr||0).toLocaleString()+' dhikr'],
    ['Devices',t.devices,'📱','var(--gold)', (t.withEmail||0)+' with email'],
    ['Data stored',null,'💾','var(--teal)', (t.subs||0)+' push subs'],
    ['Bookmarks',t.bookmarks,'🔖','var(--blue)', 'saved by users'],
  ];
  document.getElementById('kpis').innerHTML = K.map(function(s){
    var isBytes = s[1]==null;
    return '<div class="kpi" style="--acc:'+s[3]+'"><div class="ico">'+s[2]+'</div>'+
      '<div class="v" data-c="'+(isBytes?'':s[1])+'">'+(isBytes?bytes(t.bytes):'0')+'</div>'+
      '<div class="l">'+h(s[0])+'</div><div class="t'+(!s[4]?' flat':'')+'">'+h(s[4]||'—')+'</div></div>';
  }).join('');
  document.querySelectorAll('#kpis .v[data-c]').forEach(function(b){ if(b.getAttribute('data-c')!=='') countUp(b,b.getAttribute('data-c')); });

  areaChart(document.getElementById('signupsChart'), D.signups||[], '#e6c169');

  document.getElementById('accCount').textContent = (D.users.length||0)+' total';
  document.getElementById('users').innerHTML=
    '<tr><th></th><th>User</th><th>Email</th><th>Joined</th><th>Last active</th><th class="right">Devices</th>'+
    '<th class="right">Prayers</th><th class="right">Journal</th><th>Password</th><th></th></tr>'+
    (D.users.length? D.users.map(function(u,i){
      var open=OPEN[u.key];
      return '<tr class="urow'+(open?' open':'')+'" data-key="'+h(u.key)+'" onclick="expand(this.dataset.key)">'+
        '<td><span class="chev">▸</span></td>'+
        '<td><div class="uname"><span class="av">'+h(init(u.username))+'</span><b>'+h(u.username)+'</b></div></td>'+
        '<td>'+(u.email?h(u.email):'<span class="dim">none</span>')+'</td>'+
        '<td>'+when(u.createdAt)+'</td>'+
        '<td>'+h(ago(u.updatedAt))+'</td>'+
        '<td class="right mono">'+u.devices+'</td>'+
        '<td class="right mono">'+u.stats.prayerLogs+' <span class="dim">/ '+u.stats.prayerDays+'d</span></td>'+
        '<td class="right mono">'+u.stats.journal+'</td>'+
        '<td><span class="pill ok">🔒 scrypt</span></td>'+
        '<td onclick="event.stopPropagation()"><div class="acts">'+
          '<button class="btn" data-key="'+h(u.key)+'" onclick="raw(this.dataset.key)">Raw</button>'+
          '<button class="btn" data-key="'+h(u.key)+'" onclick="signout(this.dataset.key)">Sign out</button>'+
          '<button class="btn danger" data-key="'+h(u.key)+'" onclick="del(this.dataset.key)">Delete</button>'+
        '</div></td></tr>'+
        '<tr class="detail'+(open?' open':'')+'" id="det-'+h(u.key)+'"><td colspan="10"><div class="dwrap"><div class="dinner" id="din-'+h(u.key)+'">'+
          (open&&DET[u.key]?detailHTML(DET[u.key]):'<div class="panel dim">Loading…</div>')+'</div></div></td></tr>';
    }).join('') : '<tr><td colspan="10" class="dim">No accounts yet. Users appear here when they sign up in the app.</td></tr>');
  Object.keys(OPEN).forEach(function(k){ if(OPEN[k]&&DET[k]) requestAnimationFrame(function(){animateDetail(k);}); });

  document.getElementById('subs').innerHTML=
    '<tr><th>Push service</th><th>Endpoint</th><th class="right">Scheduled</th><th class="right">Pending</th><th>Updated</th></tr>'+
    (D.subs.length? D.subs.map(function(s){
      return '<tr><td>'+h(s.host)+'</td><td class="dim mono">…'+h(s.endpointTail)+'</td>'+
        '<td class="right mono">'+s.scheduled+'</td><td class="right mono">'+s.pending+'</td><td>'+when(s.updatedAt)+'</td></tr>';
    }).join('') : '<tr><td colspan="5" class="dim">No push subscriptions yet.</td></tr>');

  var s=D.server;
  var storage = s.durable
    ? '<span class="pill ok">durable · Postgres</span>'
    : '<span class="pill off">ephemeral · file</span>';
  var warn = s.durable ? '' :
    '<div class="note" style="margin:12px 0 0"><b>⚠ Accounts are NOT durable on this instance.</b> Storage is a local file on an ephemeral filesystem — every restart, redeploy or sleep <b>wipes all accounts</b>. Set a free Postgres <code>DATABASE_URL</code> in the Render dashboard so signups survive and always appear here.</div>';
  document.getElementById('server').innerHTML=
    'Push '+(s.push?'<span class="pill ok">on</span>':'<span class="pill off">off</span>')+
    ' &nbsp; Email reset '+(s.email?'<span class="pill ok">on</span>':'<span class="pill off">off</span>')+
    ' &nbsp; Storage '+storage+
    '<br><br>'+h(s.storeDesc||'')+'<br>Node '+h(s.node)+' · up '+Math.floor(s.uptimeSec/3600)+'h '+(Math.floor(s.uptimeSec/60)%60)+'m · '+h(s.now)+
    warn;
  try{ renderAlerts(D.alerts); }catch(e){}
  try{ renderDelivery(D.delivery); }catch(e){}
  try{ renderDevotion(D.devotion, t); }catch(e){}
  try{ renderRetention(D.retention); }catch(e){}
  el_updated(s);
  spy();
}
function el_updated(s){ var u=document.getElementById('updated'); if(u) u.innerHTML='<span style="color:var(--green)">●</span> live · auto-refresh'; }

/* ── Alerts: real conditions that need the owner to DO something ── */
function renderAlerts(list){
  var host=document.getElementById('alerts'); if(!host) return;
  if(!list || !list.length){ host.innerHTML=''; return; }
  var ic={critical:'⛔',warn:'⚠️',info:'ℹ️'};
  host.innerHTML=list.map(function(a,i){
    return '<div class="alert '+h(a.level)+'" style="animation-delay:'+(i*70)+'ms">'+
      '<span class="ai">'+(ic[a.level]||'•')+'</span>'+
      '<div><b>'+h(a.title)+'</b><p>'+h(a.body)+'</p></div></div>';
  }).join('');
}

/* ── Reminder delivery: the one feature that fails silently, made visible ── */
function renderDelivery(d){
  var host=document.getElementById('delivery'); if(!host) return;
  if(!d || !d.available){ host.innerHTML='<div class="empty">Delivery telemetry unavailable.</div>'; return; }
  if(!d.enabled){ host.innerHTML='<div class="empty">Push is disabled — set the VAPID keys to deliver reminders.</div>'; return; }
  var attempted=(d.total.sent||0)+(d.total.failed||0);
  var rate=d.successRate;   // null until something has actually been attempted
  var pct=(rate==null)?0:rate;
  var col=(rate==null)?'var(--dim)':(rate>=95?'#48d39a':(rate>=80?'var(--gold)':'#e0687f'));
  var C=2*Math.PI*54;
  var gauge='<div class="gauge"><svg viewBox="0 0 120 120" width="132" height="132">'+
    '<circle cx="60" cy="60" r="54" fill="none" stroke="#0c1320" stroke-width="11"/>'+
    '<circle class="gring" cx="60" cy="60" r="54" fill="none" stroke="'+col+'" stroke-width="11" stroke-linecap="round" '+
      'style="stroke-dasharray:'+C.toFixed(1)+';stroke-dashoffset:'+(C*(1-pct/100)).toFixed(1)+'"/>'+
    '</svg><div class="gv"><b style="color:'+col+'">'+(rate==null?'—':rate+'%')+'</b><span>delivered</span></div></div>';
  var m=function(label,val,max,cls){
    var w=max?Math.min(100,Math.round(val/max*100)):0;
    return '<div class="mrow"><span class="ml">'+label+'</span><span class="mbar"><i class="'+(cls||'')+'" style="width:'+w+'%"></i></span><span class="mv">'+val.toLocaleString()+'</span></div>';
  };
  var peak=Math.max(d.total.sent||0,d.total.failed||0,1);
  var meters=m('Sent',d.total.sent||0,peak,'g')+m('Failed',d.total.failed||0,peak,'r')+
             m('Timed out',d.total.timedOut||0,peak,'r')+m('Dead pruned',d.total.dead||0,peak);
  var last=d.last||{};
  host.innerHTML='<div class="opsgrid">'+gauge+'<div>'+meters+'</div></div>'+
    '<div class="statline">'+
      '<div class="stat"><b>'+(d.subscriptions||0).toLocaleString()+'</b><span>Subscribers</span></div>'+
      '<div class="stat"><b>'+(d.pending||0).toLocaleString()+'</b><span>Pending</span></div>'+
      '<div class="stat"><b>'+(d.scheduled||0).toLocaleString()+'</b><span>Scheduled</span></div>'+
      '<div class="stat"><b>'+(d.lastDurationMs||0)+'ms</b><span>Last tick</span></div>'+
      '<div class="stat"><b>'+(d.runs||0).toLocaleString()+'</b><span>Ticks run</span></div>'+
    '</div>'+
    '<div class="dim" style="font-size:12.5px;margin-top:13px">'+
      (attempted?('Last pass: '+(last.due||0)+' due · '+(last.sent||0)+' sent · '+(last.failed||0)+' failed'):
       'No reminders have come due yet — counters start once a scheduled prayer time passes.')+
      (d.lastRun?(' · last run '+ago(d.lastRun)):'')+'</div>';
}

/* ── Devotion: prayer completion across every tracked day ── */
function renderDevotion(v, t){
  var host=document.getElementById('devotion'); if(!host) return;
  if(!v){ host.innerHTML='<div class="empty">No devotion data yet.</div>'; return; }
  if(v.completion==null){ host.innerHTML='<div class="empty">No prayers tracked yet — this fills in as people log their salah.</div>'; return; }
  var col=v.completion>=80?'#48d39a':(v.completion>=50?'var(--gold)':'#e0687f');
  var C=2*Math.PI*54;
  var gauge='<div class="gauge"><svg viewBox="0 0 120 120" width="132" height="132">'+
    '<circle cx="60" cy="60" r="54" fill="none" stroke="#0c1320" stroke-width="11"/>'+
    '<circle class="gring" cx="60" cy="60" r="54" fill="none" stroke="'+col+'" stroke-width="11" stroke-linecap="round" '+
      'style="stroke-dasharray:'+C.toFixed(1)+';stroke-dashoffset:'+(C*(1-v.completion/100)).toFixed(1)+'"/>'+
    '</svg><div class="gv"><b style="color:'+col+'">'+v.completion+'%</b><span>kept</span></div></div>';
  host.innerHTML='<div class="opsgrid">'+gauge+
    '<div class="dim" style="font-size:13.5px;line-height:1.75">'+
      '<b style="color:var(--text)">'+(v.prayerLogs||0).toLocaleString()+'</b> prayers kept across '+
      '<b style="color:var(--text)">'+(v.prayerDays||0).toLocaleString()+'</b> tracked days.<br>'+
      '<b style="color:var(--text)">'+(v.engaged||0).toLocaleString()+'</b> '+((v.engaged===1)?'person has':'people have')+' logged at least one prayer.'+
    '</div></div>'+
    '<div class="statline">'+
      '<div class="stat"><b>'+(v.bestStreak||0)+'</b><span>Best streak</span></div>'+
      '<div class="stat"><b>'+(v.avgStreak||0)+'</b><span>Avg streak</span></div>'+
      '<div class="stat"><b>'+((t&&t.dhikr)||0).toLocaleString()+'</b><span>Dhikr counted</span></div>'+
      '<div class="stat"><b>'+((t&&t.journal)||0).toLocaleString()+'</b><span>Reflections</span></div>'+
    '</div>';
}

/* ── Retention: do signups stay? (cohort = week they joined) ── */
function renderRetention(list){
  var host=document.getElementById('retention'); if(!host) return;
  if(!list || !list.length){ host.innerHTML='<div class="empty">No cohorts yet.</div>'; return; }
  var any=list.some(function(c){return c.size>0;});
  if(!any){ host.innerHTML='<div class="empty">No signups in the last 6 weeks yet.</div>'; return; }
  host.innerHTML='<div class="cohorts">'+list.map(function(c,i){
    var lbl=c.weeksAgo===0?'This week':(c.weeksAgo+'w ago');
    var col=c.pct==null?'var(--dim)':(c.pct>=70?'#48d39a':(c.pct>=40?'var(--gold)':'#e0687f'));
    var bg=c.pct==null?'var(--panel2)':'color-mix(in srgb,'+col+' 12%,var(--panel2))';
    return '<div class="coh" style="animation-delay:'+(i*60)+'ms;background:'+bg+'">'+
      '<div class="cp" style="color:'+col+'">'+(c.pct==null?'—':c.pct+'%')+'</div>'+
      '<div class="cw">'+h(lbl)+'</div>'+
      '<div class="cn">'+c.retained+'/'+c.size+' active</div></div>';
  }).join('')+'</div>'+
  '<div class="dim" style="font-size:12.5px;margin-top:13px">Share of each week\\'s signups that have synced in the last 14 days.</div>';
}

function areaChart(host, data, color){
  if(!host) return;
  if(!data.length){ host.innerHTML='<div class="empty">No signups yet.</div>'; return; }
  var W=680,H=180,P=26,n=data.length;
  var max=Math.max.apply(null,data.map(function(d){return d.count;}))||1;
  var xs=function(i){return P+(W-2*P)*(i/(n-1));},ys=function(v){return H-P-(H-2*P)*(v/max);};
  var line="",area="M"+xs(0)+","+ys(0);
  data.forEach(function(d,i){var x=xs(i),y=ys(d.count);line+=(i?"L":"M")+x+","+y+" ";area+="L"+x+","+y+" ";});
  area+="L"+xs(n-1)+","+ys(0)+"Z";
  var ticks="";
  for(var i=0;i<n;i+=Math.ceil(n/6)){var dt=new Date(data[i].t*1000);
    ticks+='<text x="'+xs(i)+'" y="'+(H-7)+'" text-anchor="middle">'+(dt.getMonth()+1)+'/'+dt.getDate()+'</text>';}
  var cid='g_'+color.slice(1);
  host.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" width="100%" preserveAspectRatio="xMidYMid meet">'+
    '<defs><linearGradient id="'+cid+'" x1="0" y1="0" x2="0" y2="1">'+
    '<stop offset="0" stop-color="'+color+'" stop-opacity=".34"/><stop offset="1" stop-color="'+color+'" stop-opacity="0"/></linearGradient></defs>'+
    '<path d="'+area+'" fill="url(#'+cid+')"/><path d="'+line+'" fill="none" stroke="'+color+'" stroke-width="2.5" stroke-linejoin="round"/>'+
    '<text x="'+P+'" y="16">peak '+max+'/day</text>'+ticks+'</svg>';
}

var SPY=['s-overview','s-accounts','s-subs','s-server'];
function spy(){ var y=(window.scrollY||0)+130,cur=SPY[0];
  SPY.forEach(function(id){ var e=document.getElementById(id); if(e&&e.offsetTop<=y)cur=id; });
  document.querySelectorAll('#nav a').forEach(function(a){ a.classList.toggle('on', a.getAttribute('href')==='#'+cur); });
  var ti=document.querySelector('.topbar h1'); if(ti){ var m={'s-overview':'Overview','s-accounts':'Accounts','s-subs':'Subscriptions','s-server':'Server'}; ti.textContent=m[cur]||'Overview'; }
}
window.addEventListener('scroll',spy,{passive:true});

async function expand(key){
  OPEN[key]=!OPEN[key];
  var det=document.getElementById('det-'+key);
  if(!det) return;
  var urow=det.previousElementSibling;
  if(OPEN[key]){
    urow&&urow.classList.add('open'); det.classList.add('open');
    if(!DET[key]){
      try{ var r=await fetch('/admin/api/user/'+encodeURIComponent(key)+'/detail'); DET[key]=await r.json(); }catch(e){ DET[key]={err:1}; }
      var din=document.getElementById('din-'+key);
      if(din) din.innerHTML=DET[key].err?'<div class="panel dim">Could not load detail.</div>':detailHTML(DET[key]);
    }
    requestAnimationFrame(function(){animateDetail(key);});
  } else {
    urow&&urow.classList.remove('open'); det.classList.remove('open');
  }
}

function detailHTML(d){
  var p=d.prayer||{}, l=d.learning||{}, pw=d.password||{};
  var pwHTML='<div class="panel"><div class="ptitle">🔒 Password &amp; recovery</div>'+
    '<div class="kv"><span>Status</span><b>'+(pw.set?'<span class="pill ok">Protected</span>':'<span class="pill off">not set</span>')+'</b></div>'+
    '<div class="kv"><span>Algorithm</span><b>scrypt · salted</b></div>'+
    '<div class="kv"><span>Recovery question</span><b>'+(pw.recoveryQ?'<span class="pill ok">yes</span>':'<span class="dim">no</span>')+'</b></div>'+
    '<div class="kv"><span>Email reset pending</span><b>'+(pw.resetPending?'<span class="pill warnp">active code</span>':'<span class="dim">no</span>')+'</b></div>'+
    '<div class="kv"><span>Failed logins</span><b class="mono">'+(pw.fails||0)+'</b></div>'+
    '<p class="dim" style="font-size:11.5px;margin:10px 0 0">The real password can never be shown — only this one-way hash exists.</p></div>';
  var bars=PRAYERS.map(function(k){ var v=(p.byName&&p.byName[k])||0; var pct=p.days?Math.round(v/p.days*100):0;
    return '<div class="bar"><span>'+PMETA[k][1]+' '+PMETA[k][0]+'</span><span class="tk"><i data-w="'+pct+'"></i></span><span class="vv">'+v+'</span></div>';}).join('');
  var heat=(p.recent||[]).map(function(x){ return '<i class="c'+(x.count||0)+'" title="'+h(x.day)+': '+x.count+'/5"></i>'; }).join('');
  var prayerHTML='<div class="panel"><div class="ptitle">🕌 Prayers — prayed &amp; missed</div>'+
    '<div class="ringwrap"><div class="ring" data-p="'+(p.completion||0)+'"><b>'+(p.completion||0)+'%</b><i>kept</i></div>'+
    '<div class="bars">'+bars+'</div></div>'+
    '<div class="kv" style="margin-top:12px"><span>Prayers kept</span><b class="mono">'+(p.logged||0)+' / '+(p.total||0)+'</b></div>'+
    '<div class="kv"><span>Days tracked</span><b class="mono">'+(p.days||0)+'</b></div>'+
    '<div class="kv"><span>Best streak</span><b class="mono">'+(p.streakBest||0)+' days 🔥</b></div>'+
    (heat?'<div class="heat" title="last 21 days">'+heat+'</div>':'')+'</div>';
  var lvlPct=Math.min(100,(l.xp||0)%100);
  var chip=function(em,val,lab){ return '<div class="chip"><b data-c="'+(Number(val)||0)+'">0</b><span><span class="em">'+em+'</span>'+lab+'</span></div>'; };
  var learnHTML='<div class="panel"><div class="ptitle">🌱 Learning &amp; growth</div>'+
    '<div class="kv"><span>Level</span><b class="mono">Lv '+(l.level||1)+'</b></div>'+
    '<div class="xpbar"><i data-w="'+lvlPct+'"></i></div>'+
    '<div class="dim" style="font-size:11px;margin:5px 0 12px">'+(l.xp||0)+' XP total</div>'+
    '<div class="chips">'+chip('📿',l.dhikr,'Dhikr')+chip('🔖',l.bookmarks,'Bookmarks')+chip('🤲',l.duas,'Duʿaʾ unlocked')+chip('📖',l.adhkar,'Adhkar')+chip('🏅',l.achievements,'Badges')+chip('🔥',p.streakBest,'Best streak')+'</div></div>';
  var jHTML='<div class="panel'+(VEIL?' veiled':'')+'" id="jp-'+h(d.key)+'"><div class="ptitle">📓 Journal <span class="dim" style="text-transform:none;letter-spacing:0">('+(d.journal?d.journal.length:0)+')</span></div>'+
    ((d.journal&&d.journal.length)? d.journal.slice(0,12).map(function(e){
      return '<div class="jitem"><div class="jhead"><span>'+when(e.date)+'</span><span class="mood">'+(e.mood?h(e.mood):'')+'</span></div>'+
        '<div class="jtext">'+(e.text?h(e.text):'<span class="dim">—</span>')+'</div></div>';
    }).join('')+(d.journal.length>12?'<div class="dim" style="font-size:12px">+'+(d.journal.length-12)+' more…</div>':'')
      : '<div class="empty">No journal entries yet.</div>')+'</div>';
  var meta='<div class="panel"><div class="ptitle">🪪 Profile</div>'+
    '<div class="kv"><span>Display name</span><b>'+(d.name?h(d.name):'<span class="dim">—</span>')+'</b></div>'+
    '<div class="kv"><span>Email</span><b>'+(d.email?h(d.email):'<span class="dim">none</span>')+'</b></div>'+
    '<div class="kv"><span>City</span><b>'+(d.city?h(d.city):'<span class="dim">—</span>')+'</b></div>'+
    '<div class="kv"><span>Calc method</span><b>'+(d.method!=null?h(d.method):'<span class="dim">—</span>')+'</b></div>'+
    '<div class="kv"><span>Theme</span><b>'+(d.theme?h(d.theme):'<span class="dim">—</span>')+'</b></div>'+
    '<div class="kv"><span>Devices</span><b class="mono">'+(d.devices||0)+'</b></div>'+
    '<div class="kv"><span>Joined</span><b>'+when(d.createdAt)+'</b></div>'+
    '<div class="kv"><span>Last sync</span><b>'+when(d.updatedAt)+'</b></div>'+
    '<div class="kv"><span>Data size</span><b class="mono">'+bytes(d.bytes)+'</b></div></div>';
  return meta+pwHTML+prayerHTML+learnHTML+jHTML;
}

function animateDetail(key){
  var din=document.getElementById('din-'+key); if(!din) return;
  din.querySelectorAll('.ring[data-p]').forEach(function(r){ r.style.setProperty('--p', r.getAttribute('data-p')); });
  din.querySelectorAll('.tk i[data-w],.xpbar i[data-w]').forEach(function(i){ i.style.width=i.getAttribute('data-w')+'%'; });
  din.querySelectorAll('.chip b[data-c]').forEach(function(b){ countUp(b,b.getAttribute('data-c')); });
}
function toggleVeil(){
  VEIL=!VEIL;
  document.getElementById('veilT').classList.toggle('on',!VEIL);
  document.querySelectorAll('.panel[id^="jp-"]').forEach(function(p){ p.classList.toggle('veiled',VEIL); });
}
async function raw(key){
  var r=await fetch('/admin/api/user/'+encodeURIComponent(key)+'/raw');
  var j=await r.json();
  var w=window.open('','_blank');
  w.document.write('<meta charset="utf-8"><title>'+h(j.username)+' — stored data</title>'+
    '<style>body{background:#0b0e14;color:#e8ecf6;font:14px system-ui;padding:24px}'+
    'pre{background:#0a0d14;border:1px solid #222a3a;border-radius:10px;padding:14px;overflow:auto;font-size:12.5px}'+
    '.n{background:#1a1710;border-left:3px solid #d9b45b;padding:10px 14px;border-radius:0 8px 8px 0;color:#c9b98f;margin-bottom:14px}</style>'+
    '<h2>'+h(j.username)+' <span style="color:#8f9ab4;font-weight:400">— '+bytes(j.bytes)+'</span></h2>'+
    '<div class="n">This is this person\\'s private data — their journal reflections and prayer history. '+
    'Your app promises them this stays private. Look only when you have a real reason to.</div>'+
    '<pre>'+h(JSON.stringify(j.data,null,2))+'</pre>');
  w.document.close();
}
async function signout(key){
  if(!confirm('Sign '+key+' out of all their devices?')) return;
  await fetch('/admin/api/user/'+encodeURIComponent(key)+'/signout',{method:'POST'}); DET[key]=null; load();
}
async function del(key){
  var typed=prompt('This permanently deletes '+key+' and all their synced data.\\n\\nType the username to confirm:');
  if(typed===null) return;
  var r=await fetch('/admin/api/user/'+encodeURIComponent(key)+'/delete',
    {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:typed})});
  if(!r.ok){ var j=await r.json().catch(function(){return{}}); alert(j.error||'Could not delete.'); return; }
  delete OPEN[key]; delete DET[key]; load();
}
async function logout(){ await fetch('/admin/logout',{method:'POST'}); location.href='/admin'; }
load(true);
// Live auto-refresh: a new signup persists on the server instantly, so poll every 10s and re-render
// ONLY when the data actually changed — new users appear here on their own, no manual refresh, no flicker.
setInterval(function(){ if(document.visibilityState==='visible') load(false); }, 10000);
document.addEventListener('visibilitychange', function(){ if(document.visibilityState==='visible') load(false); });
</script>`);
}

module.exports = { mountAdmin };
