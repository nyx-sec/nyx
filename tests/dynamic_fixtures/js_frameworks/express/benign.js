// Phase 13 (Track L.11) — Express CMDI benign fixture.
//
// The `/run` route accepts a `cmd` query parameter but rejects
// everything outside an allowlist before invoking `child_process.exec`
// with a fixed argv, so the sink call is unreachable for
// attacker-controlled values.

const express = require('express');
const { execFile } = require('child_process');

const app = express();

const ALLOW = new Set(['status', 'uptime', 'version']);

function runCmd(req, res) {
    const cmd = req.query.cmd || '';
    if (!ALLOW.has(cmd)) {
        return res.status(400).send('rejected');
    }
    execFile('/usr/bin/echo', [cmd], (err, stdout) => {
        if (err) return res.status(500).send(String(err));
        res.send(stdout);
    });
}

app.get('/run', runCmd);

module.exports = { app, runCmd };
