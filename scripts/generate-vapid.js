// One-time helper: generates a VAPID key pair for Web Push.
// Run: npm run generate-vapid
// Paste the output into your .env (VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY).

const webpush = require('web-push');

const keys = webpush.generateVAPIDKeys();

console.log('\nAdd these to your .env file:\n');
console.log(`VAPID_PUBLIC_KEY=${keys.publicKey}`);
console.log(`VAPID_PRIVATE_KEY=${keys.privateKey}`);
console.log('\nThe PUBLIC key also goes into your PWA frontend (to subscribe users).');
console.log('The PRIVATE key stays server-side only. Never expose it in client code.\n');
