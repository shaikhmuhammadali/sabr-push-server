/* ═══════════════════════════════════════════════════════════════════════════
   Sirat Khushu — Admin portal  (the Django-/admin-style dashboard)

   Mounts at /admin. Shows every account on this server, their push
   subscriptions, storage use and server health, and lets you delete an
   account, sign a user out everywhere, or export the whole database.

   SECURITY — read before deploying:
   • FAILS CLOSED. With no ADMIN_KEY set, /admin refuses to serve anything.
     There is deliberately no default password: an admin panel that is open
     by default is worse than no admin panel at all.
   • Set one strong key:   ADMIN_KEY=<long random string>   in your .env
   • The key is compared with timingSafeEqual, never logged, and never sent
     back to the browser. The browser gets a random session cookie instead
     (httpOnly + SameSite=Strict + Secure in production), so the key itself
     is not sitting in the cookie jar.
   • Login is rate limited (10 tries / 15 min / IP) to make guessing useless.

   PASSWORDS ARE NOT SHOWN — they are not stored. Signup runs
   crypto.scrypt(password, per-user-salt) and keeps only that one-way hash.
   Nobody (you, me, or an attacker who steals users.json) can turn it back
   into the original password. That is the entire point, and it is what
   SECURITY.md promises your users. The portal shows *that* a password is
   set and how it is protected — never the password.

   PRIVACY — the per-user "data" blob holds that person's private journal
   reflections and prayer history. The portal shows derived COUNTS by
   default (how many entries, how big). Raw contents stay hidden unless you
   explicitly open them per-user, and the UI says so out loud.
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
    // compare a fixed-length digest so differing lengths don't throw or leak length
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
  // Every admin route goes through here. Order matters: configured? → logged in?
  function gate(req, res, next) {
    if (!ADMIN_KEY) {
      return res.status(503).type('html').send(page('Admin portal is not enabled', `
        <div class="card warn">
          <h2>Set an admin key first</h2>
          <p>This portal refuses to run without one — an admin page that is open by
             default would expose every account on this server.</p>
          <p>Add this to your server's <code>.env</code>, then restart:</p>
          <pre>ADMIN_KEY=${esc(crypto.randomBytes(24).toString('base64url'))}</pre>
          <p class="dim">(That is a freshly generated suggestion — use it, or any long random string.)</p>
        </div>`));
    }
    if (!authed(req)) return res.status(401).type('html').send(loginPage());
    next();
  }

  // ── data shaping ───────────────────────────────────────────────────────────
  // Derive per-user stats WITHOUT exposing private text.
  function statsFor(u) {
    const out = { bytes: 0, prayerDays: 0, prayerLogs: 0, journal: 0, dhikr: 0, bookmarks: 0, parsed: false };
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
      }
    } catch (_) { /* blob unreadable — keep byte size only */ }
    return out;
  }

  function subsForEmailless() {
    // push subscriptions are keyed by endpoint and are not tied to a username,
    // so we report them as their own table rather than per-user.
    return Object.keys(ctx.subs || {}).map((endpoint) => {
      const s = ctx.subs[endpoint] || {};
      const sched = Array.isArray(s.schedule) ? s.schedule : [];
      let host = '';
      try { host = new URL(endpoint).host; } catch (_) { host = '—'; }
      return {
        host,
        endpointTail: endpoint.slice(-12),
        scheduled: sched.length,
        pending: sched.filter((x) => x && !x.fired).length,
        updatedAt: s.updatedAt || null,
      };
    });
  }

  function snapshot() {
    const users = Object.keys(ctx.accounts.users).map((key) => {
      const u = ctx.accounts.users[key];
      const st = statsFor(u);
      const tokens = Object.keys(ctx.accounts.tokens || {})
        .filter((th) => ctx.accounts.tokens[th] && ctx.accounts.tokens[th].u === key).length;
      return {
        key,
        username: u.username || key,
        email: u.email || null,
        createdAt: u.createdAt || null,
        updatedAt: u.updatedAt || null,
        rev: u.rev || 0,
        devices: tokens,
        hasRecoveryQ: Boolean(u.secAHash),
        pwProtected: Boolean(u.hash && u.salt),
        stats: st,
      };
    }).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    const totalBytes = users.reduce((n, u) => n + u.stats.bytes, 0);
    const weekAgo = Date.now() - 7 * 86400000;
    return {
      users,
      subs: subsForEmailless(),
      totals: {
        users: users.length,
        activeWeek: users.filter((u) => (u.updatedAt || 0) > weekAgo).length,
        withEmail: users.filter((u) => u.email).length,
        devices: Object.keys(ctx.accounts.tokens || {}).length,
        journal: users.reduce((n, u) => n + u.stats.journal, 0),
        prayerLogs: users.reduce((n, u) => n + u.stats.prayerLogs, 0),
        bytes: totalBytes,
        subs: Object.keys(ctx.subs || {}).length,
      },
      server: {
        push: Boolean(ctx.PUSH_ENABLED),
        email: typeof ctx.MAIL_ENABLED === 'function' ? Boolean(ctx.MAIL_ENABLED()) : false,
        usersFile: ctx.USERS_STORE,
        subsFile: ctx.STORE,
        uptimeSec: Math.floor(process.uptime()),
        node: process.version,
        now: new Date().toISOString(),
      },
    };
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

  // Raw blob for ONE user — deliberately a separate, explicit call.
  app.get('/admin/api/user/:key/raw', gate, (req, res) => {
    const u = ctx.accounts.users[String(req.params.key).toLowerCase()];
    if (!u) return res.status(404).json({ error: 'no such user' });
    let parsed = null;
    try { parsed = u.data ? JSON.parse(u.data) : null; } catch (_) { parsed = null; }
    res.json({ username: u.username, bytes: u.data ? Buffer.byteLength(u.data) : 0, data: parsed });
  });

  // Full export (accounts + subs). Password hashes are stripped: they are useless
  // to you and a liability in a file that lands in your Downloads folder.
  app.get('/admin/api/export', gate, (req, res) => {
    const users = {};
    for (const k of Object.keys(ctx.accounts.users)) {
      const u = ctx.accounts.users[k];
      users[k] = { ...u };
      delete users[k].hash; delete users[k].salt;
      delete users[k].secAHash; delete users[k].secASalt;
      // The pending email-reset secret is stored as u.resetCode = {hash,exp,tries,sentAt}. The old
      // code deleted resetHash/resetExp — field names that exist NOWHERE — so resetCode.hash (an
      // unsalted SHA-256 of a 6-digit code, brute-forceable instantly) shipped in the export during
      // any live reset window. Strip the real object.
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
      ctx.saveAccounts();
    }
    res.json({ ok: true });
  });

  app.post('/admin/api/user/:key/delete', gate, (req, res) => {
    const key = String(req.params.key).toLowerCase();
    if (!ctx.accounts.users[key]) return res.status(404).json({ error: 'no such user' });
    // require the exact username as confirmation, so a stray click can't erase an account
    if (String((req.body && req.body.confirm) || '').toLowerCase() !== key) {
      return res.status(400).json({ error: 'type the username to confirm' });
    }
    delete ctx.accounts.users[key];
    for (const th of Object.keys(ctx.accounts.tokens)) if (ctx.accounts.tokens[th].u === key) delete ctx.accounts.tokens[th];
    ctx.saveAccounts();
    res.json({ ok: true });
  });

  // Analytics dashboard (/admin/analytics) — reuses this same session gate, so one login
  // covers both the accounts table and the usage overview.
  try { require('./admin-analytics').mount(app, gate, ctx); }
  catch (e) { console.error('[admin] analytics mount failed:', e.message); }

  console.log('[admin] portal mounted at /admin ' + (ADMIN_KEY ? '(key set)' : '— DISABLED: set ADMIN_KEY to enable'));
}

/* ── views ─────────────────────────────────────────────────────────────────── */
const CSS = `
:root{--bg:#0b0e14;--bg2:#121724;--line:#222a3a;--text:#e8ecf6;--dim:#8f9ab4;--gold:#d9b45b;--green:#4ec98b;--red:#e2685f}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--gold)} code,pre{font-family:ui-monospace,Consolas,monospace}
pre{background:#0a0d14;border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;font-size:13px}
.wrap{max-width:1180px;margin:0 auto;padding:26px 18px 70px}
header{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:22px;flex-wrap:wrap}
h1{font-size:1.25rem;margin:0;letter-spacing:.02em} h1 small{color:var(--dim);font-weight:400;font-size:.8rem;display:block;margin-top:3px}
.card{background:var(--bg2);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:16px}
.card.warn{border-color:#5a4a1e;background:#1a1710}
h2{font-size:.78rem;letter-spacing:.18em;text-transform:uppercase;color:var(--gold);margin:0 0 14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat{background:#0e1320;border:1px solid var(--line);border-radius:11px;padding:14px}
.stat b{display:block;font-size:1.5rem;font-variant-numeric:tabular-nums} .stat span{color:var(--dim);font-size:.76rem}
table{width:100%;border-collapse:collapse;font-size:14px} th,td{text-align:left;padding:10px 9px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--dim);font-size:.72rem;letter-spacing:.1em;text-transform:uppercase;font-weight:600}
tr:last-child td{border-bottom:0} .tblwrap{overflow-x:auto}
.btn{background:#182034;border:1px solid var(--line);color:var(--text);border-radius:9px;padding:7px 12px;font-size:13px;cursor:pointer}
.btn:hover{border-color:var(--gold)} .btn.danger{border-color:#5a2a26;color:#ffb3ad} .btn.danger:hover{border-color:var(--red)}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:.72rem;border:1px solid var(--line);color:var(--dim)}
.pill.ok{color:var(--green);border-color:#245c42} .pill.off{color:var(--red);border-color:#5a2a26}
.dim{color:var(--dim)} .right{text-align:right} .mono{font-variant-numeric:tabular-nums}
input[type=password],input[type=text]{background:#0a0d14;border:1px solid var(--line);color:var(--text);border-radius:9px;padding:11px 13px;font-size:15px;width:100%}
.login{max-width:390px;margin:14vh auto;padding:0 18px}
.note{background:#0e1320;border-left:3px solid var(--gold);padding:11px 14px;border-radius:0 9px 9px 0;color:var(--dim);font-size:13.5px;margin-bottom:14px}
.err{color:#ffb3ad;font-size:13.5px;min-height:19px;margin-top:9px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
details summary{cursor:pointer;color:var(--gold);font-size:13px}
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
    <h1>Sirat Khushu <small>admin portal</small></h1>
    <div class="card">
      <h2>Sign in</h2>
      <input id="k" type="password" placeholder="Admin key" autofocus autocomplete="current-password">
      <div class="err" id="e"></div>
      <div style="margin-top:12px"><button class="btn" id="go" style="width:100%;padding:11px">Unlock</button></div>
    </div>
    <p class="dim" style="font-size:12.5px">This is the key from <code>ADMIN_KEY</code> in your server's .env — not any user's password.</p>
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
  <header>
    <h1>Sirat Khushu <small>admin portal — every account on this server</small></h1>
    <div class="row">
      <a class="btn" href="/admin/analytics" style="text-decoration:none">📊 Analytics</a>
      <button class="btn" onclick="location.reload()">Refresh</button>
      <a class="btn" href="/admin/api/export" style="text-decoration:none">Export JSON</a>
      <button class="btn" onclick="logout()">Log out</button>
    </div>
  </header>

  <div class="note">
    <b>Passwords are not shown because they are not stored.</b> Sign-up runs
    <code>scrypt(password, per-user salt)</code> and keeps only that one-way hash, so nobody — you
    included — can turn it back into the original password. If someone is locked out, use the
    app's email reset, or delete and let them re-register.
  </div>

  <div class="card"><h2>Overview</h2><div class="grid" id="stats"></div></div>
  <div class="card"><h2>Accounts</h2><div class="tblwrap"><table id="users"></table></div></div>
  <div class="card"><h2>Push subscriptions</h2><div class="tblwrap"><table id="subs"></table></div></div>
  <div class="card"><h2>Server</h2><div id="server" class="dim" style="font-size:13.5px"></div></div>

<script>
var D=null;
function h(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function when(t){ if(!t) return '<span class="dim">—</span>'; var d=new Date(t);
  return d.toLocaleDateString(undefined,{day:'numeric',month:'short',year:'numeric'})+' <span class="dim">'+d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'})+'</span>'; }
function bytes(n){ if(!n) return '0 B'; if(n<1024) return n+' B'; if(n<1048576) return (n/1024).toFixed(1)+' KB'; return (n/1048576).toFixed(2)+' MB'; }

async function load(){
  var r=await fetch('/admin/api/snapshot'); if(r.status===401){location.reload();return;}
  D=await r.json();
  var t=D.totals;
  document.getElementById('stats').innerHTML=[
    ['Accounts',t.users],['Active this week',t.activeWeek],['With email',t.withEmail],
    ['Signed-in devices',t.devices],['Journal entries',t.journal],['Prayers logged',t.prayerLogs],
    ['Push subscriptions',t.subs],['Data stored',bytes(t.bytes)]
  ].map(function(s){return '<div class="stat"><b>'+h(s[1])+'</b><span>'+h(s[0])+'</span></div>';}).join('');

  document.getElementById('users').innerHTML=
    '<tr><th>User</th><th>Email</th><th>Joined</th><th>Last sync</th><th class="right">Devices</th>'+
    '<th class="right">Prayers</th><th class="right">Journal</th><th class="right">Size</th><th>Password</th><th></th></tr>'+
    (D.users.length? D.users.map(function(u){
      return '<tr>'+
        '<td><b>'+h(u.username)+'</b></td>'+
        '<td>'+(u.email?h(u.email):'<span class="dim">none</span>')+'</td>'+
        '<td>'+when(u.createdAt)+'</td>'+
        '<td>'+when(u.updatedAt)+'</td>'+
        '<td class="right mono">'+u.devices+'</td>'+
        '<td class="right mono">'+u.stats.prayerLogs+' <span class="dim">/ '+u.stats.prayerDays+'d</span></td>'+
        '<td class="right mono">'+u.stats.journal+'</td>'+
        '<td class="right mono">'+bytes(u.stats.bytes)+'</td>'+
        '<td><span class="pill ok">scrypt</span></td>'+
        '<td class="right row" style="justify-content:flex-end">'+
          // The key goes ONLY into a double-quoted data-key attribute (h() escapes ", so it can't
          // break out) and onclick is a CONSTANT that reads this.dataset.key — the account-controlled
          // value never enters a JS-string context. (h() alone was not enough: it doesn't escape ',
          // and HTML-attribute decoding would undo entity-escaping before an inline handler runs.)
          '<button class="btn" data-key="'+h(u.key)+'" onclick="raw(this.dataset.key)">Data</button> '+
          '<button class="btn" data-key="'+h(u.key)+'" onclick="signout(this.dataset.key)">Sign out</button> '+
          '<button class="btn danger" data-key="'+h(u.key)+'" onclick="del(this.dataset.key)">Delete</button>'+
        '</td></tr>';
    }).join('') : '<tr><td colspan="10" class="dim">No accounts yet. Users appear here when they sign up in the app.</td></tr>');

  document.getElementById('subs').innerHTML=
    '<tr><th>Push service</th><th>Endpoint</th><th class="right">Scheduled</th><th class="right">Pending</th><th>Updated</th></tr>'+
    (D.subs.length? D.subs.map(function(s){
      return '<tr><td>'+h(s.host)+'</td><td class="dim mono">…'+h(s.endpointTail)+'</td>'+
        '<td class="right mono">'+s.scheduled+'</td><td class="right mono">'+s.pending+'</td><td>'+when(s.updatedAt)+'</td></tr>';
    }).join('') : '<tr><td colspan="5" class="dim">No push subscriptions yet.</td></tr>');

  var s=D.server;
  document.getElementById('server').innerHTML=
    'Push '+(s.push?'<span class="pill ok">on</span>':'<span class="pill off">off</span>')+
    ' &nbsp; Email reset '+(s.email?'<span class="pill ok">on</span>':'<span class="pill off">off</span>')+
    '<br><br>Accounts file: <code>'+h(s.usersFile)+'</code><br>Push file: <code>'+h(s.subsFile)+'</code>'+
    '<br><br>Node '+h(s.node)+' · up '+Math.floor(s.uptimeSec/3600)+'h '+(Math.floor(s.uptimeSec/60)%60)+'m · '+h(s.now);
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
  await fetch('/admin/api/user/'+encodeURIComponent(key)+'/signout',{method:'POST'});
  load();
}

async function del(key){
  var typed=prompt('This permanently deletes '+key+' and all their synced data.\\n\\nType the username to confirm:');
  if(typed===null) return;
  var r=await fetch('/admin/api/user/'+encodeURIComponent(key)+'/delete',
    {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:typed})});
  if(!r.ok){ var j=await r.json().catch(function(){return{}}); alert(j.error||'Could not delete.'); return; }
  load();
}

async function logout(){ await fetch('/admin/logout',{method:'POST'}); location.href='/admin'; }
load();
</script>`);
}

module.exports = { mountAdmin };
