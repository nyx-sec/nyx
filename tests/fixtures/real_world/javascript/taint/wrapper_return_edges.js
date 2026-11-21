const express = require('express');
const cp = require('child_process');
const app = express();

function pass(zval, aval) { return zval; }
function toNum(s) { return Number(s); }
function build(base, extra) { let x = base; x = x + extra; return x; }

app.get('/ignored', (req, res) => {
  const t = req.query.a;
  const r = pass('ls', t);
  cp.exec(r);
  res.send('ok');
});

app.get('/returned', (req, res) => {
  const t = req.query.b;
  const r = pass(t, 'ls');
  cp.exec(r);
  res.send('ok');
});

app.get('/number', (req, res) => {
  const n = toNum(req.query.c);
  cp.exec('ls ' + n);
  res.send('ok');
});

app.get('/build', (req, res) => {
  const t = req.query.d;
  cp.exec(build('ls ', t));
  res.send('ok');
});
