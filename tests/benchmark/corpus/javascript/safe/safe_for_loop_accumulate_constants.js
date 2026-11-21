// Twin of vuln_for_loop_accumulate.js: the counted loop accumulates only
// constant names, so the command passed to exec() is not user-controlled.
const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/ls', (req, res) => {
    const names = ['a', 'b'];
    let cmd = 'ls';
    for (let i = 0; i < names.length; i++) {
        cmd = cmd + ' ' + names[i];
    }
    exec(cmd);
});
