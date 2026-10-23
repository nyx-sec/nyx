const express = require('express');
const { execSync } = require('child_process');
const app = express();

app.get('/opposite', (req, res) => {
  const cmd = req.query.cmd;
  const cfg = loadConfig();
  if (cfg === null) return;
  if (cfg !== null) {
    execSync(cmd);
  }
});

app.get('/reassigned', (req, res) => {
  const cmd = req.query.cmd;
  let cfg = loadConfig();
  if (cfg === null) return;
  cfg = loadOverride();
  if (cfg === null) {
    execSync(cmd);
  }
});
