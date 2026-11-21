const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/run', (req, res) => {
  let cmd = req.query.cmd;
  for (let i = 0; i < 3; i++) {
    cmd = cmd + ' --retry';
  }
  exec(cmd);
  res.send('ok');
});
