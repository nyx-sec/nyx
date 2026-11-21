// A command assembled with `+=` from literals only, after the tainted
// value was overwritten.  Nothing user-controlled reaches exec().
const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/ls', (req, res) => {
    let cmd = req.query.dir;
    cmd = 'ls';
    cmd += ' -l';
    exec(cmd);
});
