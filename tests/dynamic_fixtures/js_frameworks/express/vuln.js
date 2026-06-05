// Phase 13 (Track L.11) — Express CMDI vuln fixture.
//
// The `/run` route forwards a `cmd` query parameter straight into
// `child_process.exec`, so any attacker who reaches the route can
// execute arbitrary shell.  Adapter binding:
// `app.get('/run', runCmd)` with `cmd` flowing through `req.query.cmd`.

const express = require('express');
const { exec } = require('child_process');

const app = express();

function runCmd(req, res) {
    const cmd = req.query.cmd || '';
    exec('ls ' + cmd, (err, stdout) => {
        if (err) return res.status(500).send(String(err));
        res.send(stdout);
    });
}

app.get('/run', runCmd);

module.exports = { app, runCmd };
