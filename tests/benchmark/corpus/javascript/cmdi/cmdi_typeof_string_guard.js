const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/run', (req, res) => {
  const cmd = req.query.cmd;
  // Only rejects query-string arrays; any string payload passes.
  if (typeof cmd !== 'string') {
    return res.status(400).send('bad');
  }
  exec(cmd);
});
