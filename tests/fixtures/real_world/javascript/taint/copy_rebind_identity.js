const express = require('express');
const escapeHtml = require('escape-html');
const { exec } = require('child_process');
const app = express();
const DEFAULT_CMD = 'uptime';

function getDefaultCmd() { return 'ls -la'; }

app.get('/rebind', (req, res) => {
  let cmd = getDefaultCmd();
  let userCmd = cmd;
  userCmd = req.query.c;
  console.log(userCmd);
  exec(cmd);
});

app.get('/default', (req, res) => {
  let label = DEFAULT_CMD;
  if (req.query.label) {
    label = req.query.label;
  }
  console.log(label);
  exec(DEFAULT_CMD);
});

app.get('/escaped-copy', (req, res) => {
  let x = req.query.a;
  let y = x;
  y = escapeHtml(y);
  console.log(y);
  res.send(x);
});

app.get('/raw-copy', (req, res) => {
  let x = req.query.a;
  let y = x;
  res.send(y);
});
