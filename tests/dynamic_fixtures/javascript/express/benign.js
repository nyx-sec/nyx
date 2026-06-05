// Phase 13 — Express route handler, benign control.
//
// Uses execFile (no shell) so the payload bytes are never interpreted as
// shell metacharacters.  The oracle marker cannot appear in stdout because
// the inner child reads `true` and its stdio is ignored.

'use strict';
const express = require('express');
const { execFileSync } = require('child_process');

function ping(req, res) {
    const host = (req.query && req.query.host) || '';
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        execFileSync('true', [host], {
            encoding: 'utf8',
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'ignore'],
        });
        res.send('ok');
    } catch (_e) {
        res.send('err');
    }
}

void express;

module.exports = { ping };
