/* ═══════════════════════════════════════════════════════════════════════════
   Durable storage for the server's state.

   WHY THIS EXISTS
   1) DURABILITY. State used to live in two JSON files. Perfect locally and on any
      host with a real disk — but free hosts (Render free and most others) have an
      EPHEMERAL filesystem, wiped on every redeploy, restart and sleep/wake. Every
      account and synced journal would silently vanish on a restart.
   2) SCALE. The old code re-serialised and rewrote the ENTIRE user store on every
      single save. One person saving a journal line cost time proportional to the
      TOTAL number of users. Measured: 1,000 users x 100KB blobs = 98MB in RAM and a
      197ms event-loop freeze per save; 5,000 users = 246MB and 465ms. At a few
      hundred users the server would spend most of its life serialising.

   SO: two interchangeable backends behind one interface.
     • no DATABASE_URL  → JSON files, exactly as before (zero config, ideal locally
                          and for small deployments on a host with a disk)
     • DATABASE_URL set → Postgres with ONE ROW PER USER, so writing one account
                          costs the same whether there are 10 users or 100,000, and
                          the data survives anything the host does.

   Switching backends is just an env var: on first Postgres boot any existing JSON
   file is migrated in, so flipping a live server over never looks like data loss.
   ═══════════════════════════════════════════════════════════════════════════ */
'use strict';

const fs = require('fs');
const path = require('path');

const DATABASE_URL = process.env.DATABASE_URL || '';
const USE_PG = Boolean(DATABASE_URL);
const DEBOUNCE_MS = 400;

/* ── file backend ───────────────────────────────────────────────────────────────
   Writes the whole file. That is fine here: the file backend is for local dev and
   small self-hosted instances, where the store is small and a disk is present. Any
   deployment large enough for whole-file writes to hurt should be on Postgres. */
function fileBackend(paths) {
  function readJson(file, fallback) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { return fallback; }
  }
  function writeJson(file, value) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(value));
    fs.renameSync(tmp, file);              // atomic: never leaves a half-written file
  }
  return {
    kind: 'file',
    async init() {},
    async loadUsers() {
      const raw = readJson(paths.users, {});
      return { users: raw.users || {}, tokens: raw.tokens || {} };
    },
    async loadSubs() { return readJson(paths.subs, {}); },
    async loadAnalytics() { return readJson(paths.analytics, null); },
    async writeUsers(accounts /*, dirty */) { writeJson(paths.users, accounts); },
    async writeSubs(subs /*, dirty */) { writeJson(paths.subs, subs); },
    async writeAnalytics(a) { writeJson(paths.analytics, a); },
    describe() { return 'JSON files (' + paths.users + ')'; },
  };
}

/* ── postgres backend ─────────────────────────────────────────────────────────── */
function pgBackend(paths) {
  let pool = null;

  return {
    kind: 'postgres',
    async init() {
      const { Pool } = require('pg');
      pool = new Pool({
        connectionString: DATABASE_URL,
        // Managed Postgres (Neon/Supabase/Render) presents certs Node will not
        // chain-verify by default. Standard for those providers; still encrypted.
        ssl: /localhost|127\.0\.0\.1/.test(DATABASE_URL) ? false : { rejectUnauthorized: false },
        max: 4,
      });
      await pool.query('CREATE TABLE IF NOT EXISTS users (key text PRIMARY KEY, doc jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())');
      await pool.query('CREATE TABLE IF NOT EXISTS subs  (endpoint text PRIMARY KEY, doc jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())');
      // tokens are small and always rewritten together, so one row is the right shape
      await pool.query('CREATE TABLE IF NOT EXISTS meta  (key text PRIMARY KEY, doc jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())');
    },

    async loadUsers() {
      const out = { users: Object.create(null), tokens: {} };
      const r = await pool.query('SELECT key, doc FROM users');
      for (const row of r.rows) out.users[row.key] = row.doc;
      const t = await pool.query("SELECT doc FROM meta WHERE key = 'tokens'");
      if (t.rows.length) out.tokens = t.rows[0].doc || {};

      // First Postgres boot with an existing JSON file → carry it over, so switching
      // a running server to Postgres does not present as data loss.
      if (!r.rows.length && !t.rows.length) {
        try {
          const raw = JSON.parse(fs.readFileSync(paths.users, 'utf8'));
          if (raw && (raw.users || raw.tokens)) {
            Object.assign(out.users, raw.users || {});
            out.tokens = raw.tokens || {};
            await this.writeUsers(out, { all: true });
            console.log('[store] migrated ' + paths.users + ' into Postgres (' +
                        Object.keys(out.users).length + ' accounts)');
          }
        } catch (_) { /* no file to migrate */ }
      }
      return out;
    },

    async loadSubs() {
      const out = {};
      const r = await pool.query('SELECT endpoint, doc FROM subs');
      for (const row of r.rows) out[row.endpoint] = row.doc;
      if (!r.rows.length) {
        try {
          const raw = JSON.parse(fs.readFileSync(paths.subs, 'utf8'));
          if (raw && Object.keys(raw).length) {
            Object.assign(out, raw);
            await this.writeSubs(out, { all: true });
            console.log('[store] migrated ' + paths.subs + ' into Postgres');
          }
        } catch (_) {}
      }
      return out;
    },

    // Analytics is one bounded blob (per-device counts, 114 surah counters, ~15 day-sets),
    // written on a longer debounce — so it lives in a single meta row, not per-record.
    async loadAnalytics() {
      const r = await pool.query("SELECT doc FROM meta WHERE key = 'analytics'");
      if (r.rows.length) return r.rows[0].doc;
      try {
        const raw = JSON.parse(fs.readFileSync(paths.analytics, 'utf8'));
        if (raw) { await this.writeAnalytics(raw); console.log('[store] migrated analytics into Postgres'); return raw; }
      } catch (_) {}
      return null;
    },
    async writeAnalytics(a) {
      await pool.query(
        "INSERT INTO meta (key, doc, updated_at) VALUES ('analytics', $1::jsonb, now()) " +
        'ON CONFLICT (key) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()',
        [JSON.stringify(a)]);
    },

    /** Write ONLY what changed. `dirty` = { users:Set, deleted:Set, tokens:bool, all:bool } */
    async writeUsers(accounts, dirty) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        if (dirty.all) {
          for (const key of Object.keys(accounts.users)) {
            await client.query(
              'INSERT INTO users (key, doc, updated_at) VALUES ($1, $2::jsonb, now()) ' +
              'ON CONFLICT (key) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()',
              [key, JSON.stringify(accounts.users[key])]);
          }
          // drop rows for accounts that no longer exist in memory
          const keys = Object.keys(accounts.users);
          if (keys.length) await client.query('DELETE FROM users WHERE NOT (key = ANY($1))', [keys]);
          else await client.query('DELETE FROM users');
        } else {
          for (const key of dirty.users) {
            const rec = accounts.users[key];
            if (!rec) continue;                       // deleted between mark and flush
            await client.query(
              'INSERT INTO users (key, doc, updated_at) VALUES ($1, $2::jsonb, now()) ' +
              'ON CONFLICT (key) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()',
              [key, JSON.stringify(rec)]);
          }
          for (const key of dirty.deleted) {
            await client.query('DELETE FROM users WHERE key = $1', [key]);
          }
        }
        if (dirty.all || dirty.tokens) {
          await client.query(
            "INSERT INTO meta (key, doc, updated_at) VALUES ('tokens', $1::jsonb, now()) " +
            'ON CONFLICT (key) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()',
            [JSON.stringify(accounts.tokens)]);
        }
        await client.query('COMMIT');
      } catch (e) {
        try { await client.query('ROLLBACK'); } catch (_) {}
        throw e;
      } finally { client.release(); }
    },

    async writeSubs(subs, dirty) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const keys = dirty.all ? Object.keys(subs) : Array.from(dirty.users);
        for (const ep of keys) {
          const rec = subs[ep];
          if (!rec) continue;
          await client.query(
            'INSERT INTO subs (endpoint, doc, updated_at) VALUES ($1, $2::jsonb, now()) ' +
            'ON CONFLICT (endpoint) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()',
            [ep, JSON.stringify(rec)]);
        }
        for (const ep of dirty.deleted) await client.query('DELETE FROM subs WHERE endpoint = $1', [ep]);
        if (dirty.all) {
          const all = Object.keys(subs);
          if (all.length) await client.query('DELETE FROM subs WHERE NOT (endpoint = ANY($1))', [all]);
          else await client.query('DELETE FROM subs');
        }
        await client.query('COMMIT');
      } catch (e) {
        try { await client.query('ROLLBACK'); } catch (_) {}
        throw e;
      } finally { client.release(); }
    },

    describe() {
      let host = 'postgres';
      try { host = new URL(DATABASE_URL).host; } catch (_) {}
      return 'Postgres (' + host + ') — one row per user, survives restarts';
    },
  };
}

/* ── dirty-tracking writer shared by both backends ─────────────────────────────── */
function makeTracker(flushFn) {
  let users = new Set(), deleted = new Set(), tokens = false, all = false;
  let timer = null, writing = false, again = false;

  async function flush() {
    if (writing) { again = true; return; }
    if (!users.size && !deleted.size && !tokens && !all) return;
    // snapshot + reset first, so edits made during the await are not lost
    const dirty = { users, deleted, tokens, all };
    users = new Set(); deleted = new Set(); tokens = false; all = false;
    writing = true;
    try { await flushFn(dirty); }
    catch (e) {
      console.error('[store] write failed:', e.message);
      // put the work back so the next flush retries it rather than dropping data
      for (const k of dirty.users) users.add(k);
      for (const k of dirty.deleted) deleted.add(k);
      tokens = tokens || dirty.tokens; all = all || dirty.all;
    }
    finally {
      writing = false;
      if (again) { again = false; flush(); }
    }
  }
  const schedule = () => { clearTimeout(timer); timer = setTimeout(flush, DEBOUNCE_MS); };

  return {
    markKey(k) { users.add(k); deleted.delete(k); schedule(); },
    markDeleted(k) { deleted.add(k); users.delete(k); schedule(); },
    markTokens() { tokens = true; schedule(); },
    markAll() { all = true; schedule(); },
    flushNow: flush,
  };
}

function createStore(paths) {
  const backend = USE_PG ? pgBackend(paths) : fileBackend(paths);
  let accountsRef = null, subsRef = null, analyticsRef = null;

  const usersTracker = makeTracker((dirty) => backend.writeUsers(accountsRef, dirty));
  const subsTracker = makeTracker((dirty) => backend.writeSubs(subsRef, dirty));

  // Analytics is written on a LONGER debounce (bounded blob, tolerates a few seconds of
  // loss on crash). This caps write frequency no matter how many events arrive, so a busy
  // stream of read pings can never turn into a busy stream of DB writes.
  let anaTimer = null, anaWriting = false, anaAgain = false;
  async function flushAnalytics() {
    if (anaWriting) { anaAgain = true; return; }
    if (!analyticsRef) return;
    anaWriting = true;
    try { await backend.writeAnalytics(analyticsRef); }
    catch (e) { console.error('[store] analytics write failed:', e.message); }
    finally { anaWriting = false; if (anaAgain) { anaAgain = false; flushAnalytics(); } }
  }

  return {
    kind: backend.kind,
    describe: () => backend.describe(),
    init: () => backend.init(),

    // The server keeps its live objects; we only need references to serialise them.
    bind(accounts, subs) { accountsRef = accounts; subsRef = subs; },
    bindAnalytics(a) { analyticsRef = a; },

    loadUsers: () => backend.loadUsers(),
    loadSubs: () => backend.loadSubs(),
    loadAnalytics: () => backend.loadAnalytics(),
    saveAnalytics() { clearTimeout(anaTimer); anaTimer = setTimeout(flushAnalytics, 5000); },

    // On the file backend every mark rewrites the whole file anyway, so the
    // distinctions below cost nothing there and buy O(1) writes on Postgres.
    saveUser: (key) => usersTracker.markKey(key),
    deleteUser: (key) => usersTracker.markDeleted(key),
    saveTokens: () => usersTracker.markTokens(),
    saveAllUsers: () => usersTracker.markAll(),

    saveSub: (ep) => subsTracker.markKey(ep),
    deleteSub: (ep) => subsTracker.markDeleted(ep),
    saveAllSubs: () => subsTracker.markAll(),

    async flushNow() { await usersTracker.flushNow(); await subsTracker.flushNow(); await flushAnalytics(); },
  };
}

module.exports = { createStore };
