const express = require('express');
const { exec } = require('child_process');
const app = express();
const ALLOWED = ['ls', 'pwd'];
const ALLOW_MAP = { ls: true, pwd: true };

// Safe: not-found result rejects before the sink.
app.get('/a', (req, res) => {
  const cmd = req.query.cmd;
  if (ALLOWED.indexOf(cmd) === -1) {
    return res.status(400).send('bad');
  }
  exec(cmd);
});

// Safe: membership compared against false rejects before the sink.
app.get('/b', (req, res) => {
  const cmd = req.query.cmd;
  if (ALLOWED.includes(cmd) === false) {
    return res.status(400).send('bad');
  }
  exec(cmd);
});

// Safe: missing map key rejects before the sink.
app.get('/c', (req, res) => {
  const cmd = req.query.cmd;
  if (ALLOW_MAP[cmd] === undefined) {
    return res.status(400).send('bad');
  }
  exec(cmd);
});

// Vulnerable: the sink sits on the not-in-list branch.
app.get('/d', (req, res) => {
  const cmd = req.query.cmd;
  if (ALLOWED.includes(cmd) === false) {
    exec(cmd);
  }
  res.send('ok');
});

// Vulnerable: `=== false` cannot tell a missing key from a false value,
// so a missing key reaches the sink.
app.get('/e', (req, res) => {
  const cmd = req.query.cmd;
  if (ALLOW_MAP[cmd] === false) {
    return res.status(400).send('bad');
  }
  exec(cmd);
});
