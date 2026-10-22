// An HTML escaper does not make a value safe for a shell: the command
// injection stays.
const express = require('express');
const { exec } = require('child_process');
const escapeHtml = require('escape-html');
const app = express();

app.get('/run', (req, res) => {
  exec('ls ' + escapeHtml(req.query.dir), (err, out) => res.send(escapeHtml(out)));
});
