// `cmd += tainted` must define `cmd` from both its old value and the
// right-hand side, so the appended query parameter reaches exec().
const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/ls', (req, res) => {
    let cmd = 'ls ';
    cmd += req.query.dir;
    exec(cmd);
});
