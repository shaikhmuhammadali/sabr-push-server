# Sabr Voice + Push Server

One tiny server that does **two independent jobs** for the Sabr app:

1. **🔊 Voice (recite everywhere)** — `/tts` speaks any Arabic **hadith or dhikr** aloud for the app's **Recite** button. Qur'an ayahs already play a real reciter (Al‑Afasy, etc.) straight from the app with no server — but hadith and short dhikr were *never recorded by a reciter*, and a computer usually has no Arabic voice, so the app hands that text here and the server speaks it back. **This works with zero configuration — no keys, no accounts.**
2. **🔔 Push (reminders when the app is closed)** — fires prayer/ayah/hadith reminders even when Sabr isn't open. **Also zero-config now:** the server generates its own VAPID keys on first boot and persists them; setting keys via environment variables is optional (only useful to keep keys fixed across hosts).

**Both jobs now need ZERO configuration** — the server generates and saves its own push keys on first boot. The whole path is: *deploy → paste the URL into the app → done.*

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/shaikhmuhammadali/sabr-push-server)

---

## Fastest path — make Recite work everywhere (≈5 min, no config)

### 1. Deploy this folder to any free Node host
Render, Railway, Fly.io, Cyclic, Glitch — any of them. They auto‑run `npm install` then `npm start` (see `package.json`). Node 18+ is required (already declared).

- **Render (easiest):** New → Web Service → connect this repo (or drag‑drop) → it detects Node → Create. You get a URL like `https://sabr-xxxx.onrender.com`.
- **Railway:** New Project → Deploy → you get `https://…up.railway.app`.
- Any host works — a VPS, your own domain, anything on **https** is now accepted by the app.

*(No environment variables are needed for Recite.)*

### 2. Paste the URL into the app
In Sabr → **Settings → Background reminders → Push server URL**, paste your server's URL (e.g. `https://sabr-xxxx.onrender.com`) and tap out of the box.

**That's it.** Every hadith and dhikr **Recite** button across the whole app now speaks aloud. (You do *not* need to turn on background reminders for this.)

> Quick test: open `https://your-server/tts?tl=ar&q=%D8%B3%D8%A8%D8%AD%D8%A7%D9%86%20%D8%A7%D9%84%D9%84%D9%87` in a browser — you should hear "SubhanAllah".

---

## Turn on background push reminders (no setup needed)

Push keys are **generated automatically on first boot** and saved to `data/vapid.json` — the startup log says `Push: ON` from day one.

Optional environment variables (only if you want them):
| Variable | Value |
|---|---|
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` | pin your own keys (`npm run generate-vapid`) instead of auto-generated ones |
| `VAPID_SUBJECT` | `mailto:you@yourdomain.com` |
| `APP_KEY` | any long random string; set the same value in the app's **App key** field to lock writes |

> **If your free host wipes its disk on redeploy**, the server simply generates new keys — and the app detects the change next time it opens and silently re-subscribes. Reminders keep working with no action from you.

### Connect in the app
Sabr → **Settings → Background reminders** → (URL is already set) → tap **Turn on background reminders** and allow notifications.

### 4. If your host sleeps (free tiers)
Create a free 1‑minute job at **cron‑job.org** or **UptimeRobot** hitting `https://your-server/tick`. That fires due reminders *and* keeps the host awake.

---

## Endpoints
| Method | Path | Purpose | Needs VAPID? |
|---|---|---|---|
| GET | `/health` | status: `{tts, push, subs}` | no |
| GET | `/tts?tl=ar&q=…` | **voices Arabic aloud** (audio/mpeg + CORS) — the Recite feature | **no** |
| GET | `/vapid` | returns the push public key | yes |
| POST | `/subscribe` | `{subscription, schedule}` — upsert a subscriber + its reminder queue | yes |
| POST | `/unsubscribe` | `{endpoint}` — remove | yes |
| GET/POST | `/tick` | fire everything due now (call every minute if your host sleeps) | yes |

## What changed in v2 (why this replaces the older server)
- **Added `/tts`** — the recite endpoint was missing, so hadith/dhikr recite could never work through the server. It's back, with server‑side multi‑chunk concatenation (handles long dhikr) and an in‑memory cache.
- **Matched the app's real API** — the app calls `/vapid`, `/subscribe {subscription, schedule}`, `/unsubscribe {endpoint}`; the previous build used different routes/shapes, so nothing connected.
- **Fixed two deploy‑breakers** — helmet's default `Cross-Origin-Resource-Policy` was blocking the cross‑origin `/tts` audio, and the JSON body limit (20 kb) was too small for the reminder schedule (~150 kb). Both fixed.
- **Decoupled voice from push** — `/tts` runs with no keys; push only activates when VAPID is set. So you can use recite without ever touching push.
- **Zero native modules** — dropped `better-sqlite3` for a tiny JSON file store, so it builds on any free host with no compilation. The app re‑uploads its schedule on every open, so a restart loses nothing.

## Honest limits
- **Recite of hadith/dhikr is a synthetic Arabic voice, not a qari.** No reciter on earth recorded hadith or dhikr audio — only the Qur'an. Qur'an ayahs always use the real reciter; this endpoint gives everything else a clear, correct spoken voice.
- **iPhone push** needs iOS **16.4+** and the app added to the Home Screen first.
- **Privacy:** the server stores only your push endpoint + queued reminder text (e.g. "Maghrib — time to pray"). No name, password, journal, or coordinates. Set `APP_KEY` to lock writes to your app only.
