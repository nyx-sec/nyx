// Phase 13 — Next.js API route handler, benign control.
//
// execFile (no shell) so payload bytes never reach a shell.
//
// nyx-shape: next

'use strict';
try { require.resolve('next'); } catch (_e) {}

const { execFileSync } = require('child_process');

module.exports = async function handler(req, res) {
    const host = (req.query && req.query.host) || '';
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        execFileSync('true', [host], {
            encoding: 'utf8',
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'ignore'],
        });
        res.status(200).send('ok');
    } catch (_e) {
        res.status(200).send('err');
    }
};
