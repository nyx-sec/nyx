// Empty-string fallback on a secret-named env var is not a hardcoded
// secret. Developers commonly write `|| ""` to satisfy TypeScript's
// non-undefined string typing while leaving the actual secret to be
// supplied at runtime. The `ts.secrets.fallback_secret` /
// `js.secrets.fallback_secret` patterns must not fire here.

const stripeApiKey: string = process.env.STRIPE_API_KEY || "";
const sendgridKey: string = process.env.SENDGRID_API_KEY || '';
const sessionSecret: string = process.env.SESSION_SECRET || "";
const vapidPrivateKey: string = process.env.VAPID_PRIVATE_KEY || "";
const calendsoEncryptionKey: string = process.env.CALENDSO_ENCRYPTION_KEY || "";

export function bootstrap() {
    return {
        stripeApiKey,
        sendgridKey,
        sessionSecret,
        vapidPrivateKey,
        calendsoEncryptionKey,
    };
}
