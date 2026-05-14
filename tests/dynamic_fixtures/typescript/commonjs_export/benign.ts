// Phase 13 — CommonJS export, benign control.

'use strict';
const { execFileSync } = require('child_process');

function runPing(host) {
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        execFileSync('true', [host], {
            encoding: 'utf8',
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'ignore'],
        });
        return 'ok';
    } catch (_e) {
        return 'err';
    }
}

module.exports = { runPing };
