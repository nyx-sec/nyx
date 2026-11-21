const express = require('express');
const cp = require('child_process');
const app = express();

function fromQuery(req) { return req.query.cmd; }
function fromBody(req) { return req.body; }
function fromEnv() { return process.env.CMD; }
function constant() { return 'ls'; }
function makeReader(req) { return () => req.query.cmd; }

app.get('/query', (req, res) => {
  const cmd = fromQuery(req);
  cp.exec(cmd);
  res.send('ok');
});

app.post('/body', (req, res) => {
  const cmd = fromBody(req);
  cp.exec(cmd);
  res.send('ok');
});

app.get('/env', (req, res) => {
  const cmd = fromEnv();
  cp.exec(cmd);
  res.send('ok');
});

app.get('/constant', (req, res) => {
  const cmd = constant();
  cp.exec(cmd);
  res.send('ok');
});

app.get('/closure', (req, res) => {
  const reader = makeReader(req);
  cp.exec(String(typeof reader));
  res.send('ok');
});
