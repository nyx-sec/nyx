// `i++` from 0 makes the branch condition true.  Leaving `i` at its
// initial constant folded `i === 1` to false and pruned the exec.
const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/run', (req, res) => {
    let i = 0;
    i++;
    if (i === 1) {
        exec(req.query.cmd);
    }
});
