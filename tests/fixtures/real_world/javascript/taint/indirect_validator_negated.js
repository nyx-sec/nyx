const express = require('express');
const { exec } = require('child_process');
const app = express();

// Safe: `!ok` rejects, so the sink only sees a validated command.
app.get('/a', (req, res) => {
  const cmd = req.query.cmd;
  const ok = isValidCommand(cmd);
  if (!ok) {
    return res.status(400).send('bad');
  }
  exec(cmd);
});

// Safe: same guard spelled as a comparison against false.
app.get('/b', (req, res) => {
  const cmd = req.query.cmd;
  const ok = isValidCommand(cmd);
  if (ok === false) {
    return res.status(400).send('bad');
  }
  exec(cmd);
});

// Vulnerable: the sink runs exactly when validation failed.
app.get('/c', (req, res) => {
  const cmd = req.query.cmd;
  const ok = isValidCommand(cmd);
  if (!ok) {
    exec(cmd);
  }
  res.send('x');
});

// Vulnerable: `!err` returns on success, so the sink sees the error case.
app.get('/d', (req, res) => {
  const cmd = req.query.cmd;
  const err = validateCommand(cmd);
  if (!err) {
    return res.send('ok');
  }
  exec(cmd);
});
