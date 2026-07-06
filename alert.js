// Optional: pings your existing Telegram bot when something needs attention.
// Safe no-op if TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID aren't set.

const TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;

let lastSentAt = 0;
const MIN_GAP_MS = 60 * 1000; // don't spam yourself more than once a minute

async function alertTelegram(message) {
  if (!TOKEN || !CHAT_ID) return;

  const now = Date.now();
  if (now - lastSentAt < MIN_GAP_MS) return; // basic self-rate-limit
  lastSentAt = now;

  try {
    await fetch(`https://api.telegram.org/bot${TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: CHAT_ID, text: `[sabr-push-server] ${message}` }),
    });
  } catch (e) {
    // Never let alerting itself crash the server
    console.error('[alert] failed to notify Telegram:', e.message);
  }
}

module.exports = { alertTelegram };
