// Empty-string fallback on a secret-named env var is not a hardcoded
// secret — `js.secrets.fallback_secret` must not fire on this shape.

const stripeApiKey = process.env.STRIPE_API_KEY || "";
const sendgridKey = process.env.SENDGRID_API_KEY || '';
const sessionSecret = process.env.SESSION_SECRET || "";
const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY || "";

module.exports = { stripeApiKey, sendgridKey, sessionSecret, vapidPrivateKey };
