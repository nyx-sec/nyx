// Phase 13 — CommonJS export, vulnerable.
//
// Synchronous `execSync` with shell:true via string concat.  Stdlib only.

'use strict';
const { execSync } = require('child_process');

function runPing(host) {
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        const out = execSync('echo hello ' + host, { encoding: 'utf8', timeout: 5000 });
        process.stdout.write(out);
        return out;
    } catch (e) {
        const out = (e.stdout || '') + (e.stderr || '');
        process.stdout.write(out);
        return out;
    }
}

module.exports = { runPing };
