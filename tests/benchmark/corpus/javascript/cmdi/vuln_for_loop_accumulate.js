// Arguments accumulated over a counted `for` loop reach exec().  The
// counter's update clause must be a real definition, or the loop phi
// collapses and the loop-carried taint is dropped.
const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/ls', (req, res) => {
    const names = req.query.names;
    let cmd = 'ls';
    for (let i = 0; i < names.length; i++) {
        cmd = cmd + ' ' + names[i];
    }
    exec(cmd);
});
