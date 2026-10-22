const express = require('express');
const { exec } = require('child_process');
const app = express();

app.post('/list', (req, res) => {
    const body = req.body;
    exec('ls ' + body.dir);
    res.send('ok');
});
