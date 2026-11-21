const cp = require('child_process');
const { spawn, spawnSync, execFileSync, fork } = require('child_process');
const express = require('express');
const app = express();

app.get('/alias', (req, res) => {
  cp.exec('ls ' + req.query.dir);
  res.end();
});

app.get('/require-inline', (req, res) => {
  require('child_process').spawn(req.query.prog, []);
  res.end();
});

app.get('/destructured-sync', (req, res) => {
  execFileSync(req.query.bin);
  res.end();
});

app.get('/fork', (req, res) => {
  fork(req.query.mod);
  res.end();
});

app.get('/shell-option', (req, res) => {
  spawn('ls', ['-la', req.query.dir], { shell: true });
  res.end();
});

app.get('/split-shell', (req, res) => {
  const dir = req.query.dir;
  spawnSync('bash', ['-c', 'ls ' + dir]);
  res.end();
});

// Safe shapes below: the argv array reaches the program verbatim, and the
// options object is not part of the command.
app.get('/argv', (req, res) => {
  spawn('ls', ['-la', req.query.dir]);
  res.end();
});

app.get('/argv-file', (req, res) => {
  cp.execFile('git', ['log', req.query.ref], () => res.end());
});

app.get('/options', (req, res) => {
  cp.exec('ls', { cwd: req.query.dir }, () => res.end());
});

app.get('/shell-off', (req, res) => {
  spawn('ls', ['-la', req.query.dir], { shell: false });
  res.end();
});
