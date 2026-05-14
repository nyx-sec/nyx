// Phase 13 — bare async function, vulnerable.
//
// Stdlib-only.  Async function awaits `child_process.exec` via util.promisify
// so the harness's `await _entry.runPing(payload)` resolves before the
// process exits.

'use strict';
const { exec } = require('child_process');
const { promisify } = require('util');
const execP = promisify(exec);

async function runPing(host) {
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        const { stdout } = await execP('echo hello ' + host, { timeout: 5000 });
        process.stdout.write(stdout);
        return stdout;
    } catch (e) {
        const out = (e.stdout || '') + (e.stderr || '');
        process.stdout.write(out);
        return out;
    }
}

module.exports = { runPing };
