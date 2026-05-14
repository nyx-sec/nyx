// Phase 13 — bare async function, benign control.
//
// execFile (no shell) via util.promisify(execFile).  Payload never reaches a
// shell; stderr silenced so payload bytes do not leak via the inner process'
// error message.

'use strict';
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileP = promisify(execFile);

async function runPing(host) {
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        const { stdout } = await execFileP('true', [host], {
            timeout: 5000,
        });
        return stdout;
    } catch (_e) {
        return 'err';
    }
}

module.exports = { runPing };
