// Phase 11 (Track J.9) — JavaScript DATA_EXFIL benign control fixture.
const http = require('http');

const ALLOWLIST = new Set(['127.0.0.1', 'localhost']);

function run(host) {
    if (!ALLOWLIST.has(host)) return;
    const secret = 'alice-creds';
    const req = http.request({
        host,
        path: '/exfil?token=' + encodeURIComponent(secret),
        method: 'POST',
    });
    req.end();
}

module.exports = { run };
