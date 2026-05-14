// Phase 13 — Express route handler, vulnerable.
//
// Vulnerable handler concatenates `req.query.host` into a shell command.
// Harness builds a mock req/res via js_shared::emit_express and dispatches
// synchronously; we never bind a real listener.

'use strict';
const express = require('express');
const { execSync } = require('child_process');

function ping(req, res) {
    const host = (req.query && req.query.host) || '';
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        const out = execSync('echo hello ' + host, { encoding: 'utf8', timeout: 5000 });
        res.send(out);
    } catch (e) {
        res.send((e.stdout || '') + (e.stderr || ''));
    }
}

// Touch the dep so the materialised package.json's `express` pin survives
// shake-down by `npm install --no-save`; harness never starts the server.
void express;

module.exports = { ping };
