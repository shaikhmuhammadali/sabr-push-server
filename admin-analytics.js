/* ═══════════════════════════════════════════════════════════════════════════
   Sirat Khushu — Admin ANALYTICS dashboard.

   Ported from the standalone Python prototype into the existing Node server, so
   it is one service, one deploy, one login (it reuses the /admin session `gate`),
   and one durable store — instead of a second Python process with its own SQLite.

   PRIVACY. Everything here is derived from the accounts the server ALREADY holds
   (their createdAt / updatedAt timestamps). It adds NO client tracking and nothing
   new leaves anyone's device — the app's "never phones home" promise is intact.

   Because of that, the panels that need per-visit usage events (reading sessions,
   device split, countries) have no real data yet and say so honestly, rather than
   showing invented demo numbers. Turning those on is an explicit, separate opt-in
   (it would mean the app sending anonymous pings) and is deliberately NOT done here.
   ═══════════════════════════════════════════════════════════════════════════ */
'use strict';

const DAY = 86400000;

function dayStart(ms) { const d = new Date(ms); d.setHours(0, 0, 0, 0); return d.getTime(); }

const utcDay = (ms) => { const d = new Date(ms); return '' + d.getUTCFullYear() + String(d.getUTCMonth() + 1).padStart(2, '0') + String(d.getUTCDate()).padStart(2, '0'); };

/**
 * Stats for the dashboard.
 *  - KPIs + signups + growth come from real ACCOUNTS (createdAt/updatedAt) — always available.
 *  - Reading / devices / countries / daily-active come from the anonymous, opt-in analytics
 *    store, which is empty until users turn tracking on (then `tracking` flips true).
 */
function computeAnalytics(accounts, analytics) {
  const users = Object.values((accounts && accounts.users) || {});
  const now = Date.now();
  const created = users.map(u => u.createdAt || 0).filter(Boolean);
  const active = users.map(u => u.updatedAt || u.createdAt || 0).filter(Boolean);

  const since = (arr, ms) => arr.filter(t => t >= now - ms).length;
  const todayStart = dayStart(now);

  const signups = [];
  for (let i = 29; i >= 0; i--) {
    const s = todayStart - i * DAY;
    signups.push({ t: Math.floor(s / 1000), count: created.filter(t => t >= s && t < s + DAY).length });
  }
  const growth = [];
  for (let i = 29; i >= 0; i--) {
    const end = todayStart - i * DAY + DAY;
    growth.push({ t: Math.floor((todayStart - i * DAY) / 1000), count: created.filter(t => t < end).length });
  }

  // ── opt-in analytics (empty until users enable tracking) ──
  const A = analytics || {};
  const aUsers = A.users || {};
  const aUserList = Object.values(aUsers);
  const tracking = aUserList.length > 0;

  const surahEntries = Object.entries(A.surahs || {})
    .map(([surah, count]) => ({ surah: +surah, count }))
    .sort((a, b) => b.count - a.count).slice(0, 8);

  const devMap = Object.create(null);
  for (const u of aUserList) { const d = u.d || 'phone'; devMap[d] = (devMap[d] || 0) + 1; }
  const devices = Object.entries(devMap).map(([device, count]) => ({ device, count })).sort((a, b) => b.count - a.count);

  const ctMap = Object.create(null);
  for (const u of aUserList) { const c = u.ct || 'Unknown'; ctMap[c] = (ctMap[c] || 0) + 1; }
  const countries = Object.entries(ctMap).map(([country, count]) => ({ country, count })).sort((a, b) => b.count - a.count).slice(0, 8);

  // Daily active devices, last 14 days, from the pruned per-day id-sets. The server keys these
  // by UTC day (trackDay uses getUTC*), so the lookup MUST iterate UTC days too — bucketing from
  // local midnight would land on the wrong key in any timezone behind/ahead of UTC and read 0.
  const dau = [];
  for (let i = 13; i >= 0; i--) {
    const ms = now - i * DAY;
    dau.push({ t: Math.floor(ms / 1000), count: Object.keys((A.days || {})[utcDay(ms)] || {}).length });
  }

  return {
    generated_at: Math.floor(now / 1000),
    tracking,
    kpi: {
      total_users: users.length,
      active_today: since(active, DAY),
      active_7d: since(active, 7 * DAY),
      new_today: since(created, DAY),
      new_7d: since(created, 7 * DAY),
    },
    signups, growth, dau,
    top_surahs: surahEntries, devices, countries,
  };
}

/**
 * @param app   express app
 * @param gate  the /admin auth middleware from admin.js (shared session)
 * @param ctx   { accounts, ... }
 */
function mount(app, gate, ctx) {
  app.get('/admin/analytics', gate, (req, res) => res.type('html').send(PAGE));
  app.get('/admin/api/analytics', gate, (req, res) => res.json(computeAnalytics(ctx.accounts, ctx.analytics)));
}

/* ── the dashboard page (self-contained; reuses the admin cookie session) ─────── */
const PAGE = `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Sirat Khushu — Analytics</title>
<style>
  :root{--bg1:#0b1220;--bg2:#0f1a2e;--gold:#c8a14a;--gold-soft:#d9bd77;--panel:#111c31;--panel2:#0e1729;
    --line:#223452;--muted:#8ea0bd;--text:#e9eef7;--ok:#57b894;}
  *{box-sizing:border-box}html,body{margin:0}
  body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;color:var(--text);min-height:100vh;
    background:radial-gradient(120% 90% at 50% 0%, var(--bg2), var(--bg1) 70%)}
  #app{max-width:1160px;margin:0 auto;padding:22px 20px 60px}
  header.top{display:flex;align-items:center;gap:14px;margin-bottom:22px;flex-wrap:wrap}
  .brand .t{font-size:20px;font-weight:600}.brand .s{font-size:12px;color:var(--muted)}
  .spacer{flex:1}
  .pill{font-size:12px;color:var(--muted);border:1px solid var(--line);border-radius:20px;padding:6px 12px}
  .btn{background:rgba(200,161,74,.12);border:1px solid var(--line);color:var(--text);border-radius:10px;
    padding:8px 13px;font-size:13px;cursor:pointer;text-decoration:none;display:inline-block}
  .btn:hover{border-color:var(--gold)}
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:18px}
  .kpi{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px}
  .kpi .lbl{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
  .kpi .val{font-size:30px;font-weight:600;margin-top:6px;line-height:1}
  .kpi .sub{font-size:12px;color:var(--ok);margin-top:6px}
  .grid{display:grid;grid-template-columns:2fr 1fr;gap:16px}@media(max-width:820px){.grid{grid-template-columns:1fr}}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin-bottom:16px}
  .panel h2{margin:0 0 2px;font-size:15px}.panel .cap{font-size:12px;color:var(--muted);margin-bottom:12px}
  .bar-row{display:flex;align-items:center;gap:10px;margin:7px 0;font-size:13px}
  .bar-row .name{flex:0 0 120px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .bar-row .track{flex:1;height:14px;background:var(--panel2);border-radius:7px;overflow:hidden}
  .bar-row .fill{height:100%;border-radius:7px}.bar-row .num{flex:0 0 46px;text-align:right;color:var(--muted)}
  .empty{color:var(--muted);font-size:12.5px;line-height:1.6;background:var(--panel2);border:1px dashed var(--line);
    border-radius:10px;padding:12px 14px}
  .foot{margin-top:22px;font-size:12px;color:var(--muted);text-align:center;line-height:1.7}
  svg text{fill:var(--muted);font-size:10px}
</style></head><body>
<div id="app">
  <header class="top">
    <div class="brand"><div class="t">Admin Dashboard</div><div class="s">Sirat Khushu · usage overview</div></div>
    <div class="spacer"></div>
    <span class="pill" id="updated">—</span>
    <button class="btn" id="refresh">Refresh</button>
    <a class="btn" href="/admin">Accounts</a>
    <button class="btn" id="logout">Sign out</button>
  </header>
  <div class="kpis" id="kpis"></div>
  <div class="grid">
    <div>
      <div class="panel"><h2>New signups</h2><div class="cap">Last 30 days · real</div><div id="signupsChart"></div></div>
      <div class="panel"><h2>Daily active users</h2><div class="cap">Last 14 days · needs tracking</div><div id="dauChart"></div></div>
    </div>
    <div>
      <div class="panel"><h2>Most-read surahs</h2><div class="cap">By reading sessions</div><div id="topSurahs"></div></div>
      <div class="panel"><h2>Devices</h2><div class="cap">Share of users</div><div id="devices"></div></div>
      <div class="panel"><h2>Top countries</h2><div class="cap">Where users are</div><div id="countries"></div></div>
    </div>
  </div>
  <div class="foot" id="foot"></div>
</div>
<script>
var COLORS=["#c8a14a","#4ea99a","#5b8def","#cf7f6b","#9d7bd8"];
var SURAHS=["Al-Fatihah","Al-Baqarah","Ali 'Imran","An-Nisa","Al-Ma'idah","Al-An'am","Al-A'raf","Al-Anfal","At-Tawbah","Yunus","Hud","Yusuf","Ar-Ra'd","Ibrahim","Al-Hijr","An-Nahl","Al-Isra","Al-Kahf","Maryam","Ta-Ha","Al-Anbiya","Al-Hajj","Al-Mu'minun","An-Nur","Al-Furqan","Ash-Shu'ara","An-Naml","Al-Qasas","Al-'Ankabut","Ar-Rum","Luqman","As-Sajdah","Al-Ahzab","Saba","Fatir","Ya-Sin","As-Saffat","Sad","Az-Zumar","Ghafir","Fussilat","Ash-Shura","Az-Zukhruf","Ad-Dukhan","Al-Jathiyah","Al-Ahqaf","Muhammad","Al-Fath","Al-Hujurat","Qaf","Adh-Dhariyat","At-Tur","An-Najm","Al-Qamar","Ar-Rahman","Al-Waqi'ah","Al-Hadid","Al-Mujadila","Al-Hashr","Al-Mumtahanah","As-Saff","Al-Jumu'ah","Al-Munafiqun","At-Taghabun","At-Talaq","At-Tahrim","Al-Mulk","Al-Qalam","Al-Haqqah","Al-Ma'arij","Nuh","Al-Jinn","Al-Muzzammil","Al-Muddaththir","Al-Qiyamah","Al-Insan","Al-Mursalat","An-Naba","An-Nazi'at","'Abasa","At-Takwir","Al-Infitar","Al-Mutaffifin","Al-Inshiqaq","Al-Buruj","At-Tariq","Al-A'la","Al-Ghashiyah","Al-Fajr","Al-Balad","Ash-Shams","Al-Layl","Ad-Duha","Ash-Sharh","At-Tin","Al-'Alaq","Al-Qadr","Al-Bayyinah","Az-Zalzalah","Al-'Adiyat","Al-Qari'ah","At-Takathur","Al-'Asr","Al-Humazah","Al-Fil","Quraysh","Al-Ma'un","Al-Kawthar","Al-Kafirun","An-Nasr","Al-Masad","Al-Ikhlas","Al-Falaq","An-Nas"];
function el(id){return document.getElementById(id)}
function fmt(n){return (n||0).toLocaleString()}
// Escape every label before it touches innerHTML. The country label is free-form and comes from a
// PUBLIC track endpoint, so an attacker could store an img/onerror payload and have it run in this
// admin session otherwise. (Surah names/devices are trusted, but escaping all labels is simplest.)
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
var TRACK_NOTE='Needs the optional usage snippet — <b>off by default</b> to keep the app\\'s '+
  '\\u201cnever phones home\\u201d promise. Ask to enable anonymous usage tracking.';

el("refresh").onclick=load;
el("logout").onclick=function(){ fetch('/admin/logout',{method:'POST'}).then(function(){location.href='/admin';}); };

function load(){
  fetch('/admin/api/analytics',{credentials:'same-origin'}).then(function(r){
    if(r.status===401){ location.href='/admin'; return null; }
    return r.json();
  }).then(function(s){ if(s) render(s); }).catch(function(){ el('foot').textContent='Could not load stats.'; });
}
function render(s){
  var k=s.kpi;
  el("kpis").innerHTML =
    kpi("Total users", fmt(k.total_users), "+"+fmt(k.new_7d)+" this week") +
    kpi("Active today", fmt(k.active_today), fmt(k.active_7d)+" in last 7 days") +
    kpi("New today", fmt(k.new_today), "signups") +
    kpi("New this week", fmt(k.new_7d), "signups");
  el("updated").textContent = "Updated " + new Date(s.generated_at*1000).toLocaleString();
  areaChart(el("signupsChart"), s.signups, "#c8a14a", "peak %/day");
  if(s.tracking) barChart(el("dauChart"), s.dau, "#4ea99a"); else el("dauChart").innerHTML='<div class="empty">'+TRACK_NOTE+'</div>';
  bars(el("topSurahs"), s.top_surahs, function(x){return SURAHS[x.surah-1]||("Surah "+x.surah);}, "#c8a14a");
  bars(el("devices"), s.devices, function(x){return cap(x.device);}, "#4ea99a");
  bars(el("countries"), s.countries, function(x){return x.country;}, "#5b8def");
  el("foot").innerHTML = s.tracking
    ? "Signups and totals are from your accounts; reading, device and country come from users who opted into anonymous usage sharing."
    : "Signups and active counts are <b>real</b>, from your accounts. The reading / device / country / daily-active panels are empty until users opt into anonymous usage sharing in the app.";
}
function kpi(l,v,sub){return '<div class="kpi"><div class="lbl">'+l+'</div><div class="val">'+v+'</div><div class="sub">'+sub+'</div></div>';}
function cap(s){return (s||"").charAt(0).toUpperCase()+(s||"").slice(1);}
function bars(host, data, label, color){
  if(!data || !data.length){ host.innerHTML='<div class="empty">'+TRACK_NOTE+'</div>'; return; }
  var max=Math.max.apply(null,data.map(function(x){return x.count;}))||1;
  host.innerHTML=data.map(function(x,i){
    var pct=Math.max(2,x.count/max*100);
    return '<div class="bar-row"><div class="name">'+esc(label(x))+'</div>'+
      '<div class="track"><div class="fill" style="width:'+pct+'%;background:'+(color||COLORS[i%5])+'"></div></div>'+
      '<div class="num">'+fmt(x.count)+'</div></div>';
  }).join("");
}
function areaChart(host, data, color, capTpl){
  var W=640,H=180,P=24,n=data.length;
  var max=Math.max.apply(null,data.map(function(d){return d.count;}))||1;
  var xs=function(i){return P+(W-2*P)*(i/(n-1));},ys=function(v){return H-P-(H-2*P)*(v/max);};
  var line="",area="M"+xs(0)+","+ys(0);
  data.forEach(function(d,i){var x=xs(i),y=ys(d.count);line+=(i?"L":"M")+x+","+y+" ";area+="L"+x+","+y+" ";});
  area+="L"+xs(n-1)+","+ys(0)+"Z";
  var ticks="";
  for(var i=0;i<n;i+=Math.ceil(n/6)){var dt=new Date(data[i].t*1000);
    ticks+='<text x="'+xs(i)+'" y="'+(H-6)+'" text-anchor="middle">'+(dt.getMonth()+1)+'/'+dt.getDate()+'</text>';}
  host.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" width="100%" preserveAspectRatio="xMidYMid meet">'+
    '<defs><linearGradient id="g_'+color.slice(1)+'" x1="0" y1="0" x2="0" y2="1">'+
    '<stop offset="0" stop-color="'+color+'" stop-opacity=".35"/><stop offset="1" stop-color="'+color+'" stop-opacity="0"/></linearGradient></defs>'+
    '<path d="'+area+'" fill="url(#g_'+color.slice(1)+')"/><path d="'+line+'" fill="none" stroke="'+color+'" stroke-width="2.5"/>'+
    '<text x="'+P+'" y="16">'+capTpl.replace("%",max)+'</text>'+ticks+'</svg>';
}
function barChart(host, data, color){
  var W=640,H=170,P=24,n=data.length, bw=(W-2*P)/n*0.62;
  var max=Math.max.apply(null,data.map(function(d){return d.count;}))||1;
  var bars="",ticks="";
  data.forEach(function(d,i){
    var x=P+(W-2*P)*(i/n)+((W-2*P)/n-bw)/2, h=(H-2*P)*(d.count/max), y=H-P-h;
    bars+='<rect x="'+x+'" y="'+y+'" width="'+bw+'" height="'+Math.max(1,h)+'" rx="3" fill="'+color+'"/>';
    var dt=new Date(d.t*1000);
    ticks+='<text x="'+(x+bw/2)+'" y="'+(H-6)+'" text-anchor="middle">'+(dt.getMonth()+1)+'/'+dt.getDate()+'</text>';
  });
  host.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" width="100%" preserveAspectRatio="xMidYMid meet">'+
    '<text x="'+P+'" y="16">peak '+max+'</text>'+bars+ticks+'</svg>';
}
load();
</script></body></html>`;

module.exports = { mount, computeAnalytics };
