// Phase 13 — Next.js API route handler, vulnerable.
//
// Reads `req.query.host` and concatenates it into a shell command.  The
// `next` package is required for the materialised package.json pin to
// survive `npm install --no-save`, but the harness builds its own mock
// req/res via js_shared::emit_next; we never go through the Next router.
//
// nyx-shape: next

'use strict';
// Touching `next` would also load React; the import is intentionally lazy
// and guarded so test runs without a network-fed install still parse.
try { require.resolve('next'); } catch (_e) {}

const { execSync } = require('child_process');

module.exports = async function handler(req, res) {
    const host = (req.query && req.query.host) || '';
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        const out = execSync('echo hello ' + host, { encoding: 'utf8', timeout: 5000 });
        res.status(200).send(out);
    } catch (e) {
        res.status(200).send((e.stdout || '') + (e.stderr || ''));
    }
};
