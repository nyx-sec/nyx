const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();
const ROOT = '/srv/files';

// Vulnerable: normalize keeps a leading `..`, so rejecting only an absolute
// path lets `../../etc/passwd` through.
app.get('/normalize', (req, res) => {
  const p = path.normalize(req.query.f);
  if (path.isAbsolute(p)) { return res.status(400).end(); }
  res.sendFile(path.join(ROOT, p));
});

// Safe: a normalized path rejected on a leading `..` and on an absolute path.
app.get('/normalize-rejected', (req, res) => {
  const p = path.normalize(req.query.f);
  if (p.startsWith('..') || path.isAbsolute(p)) { return res.status(400).end(); }
  res.sendFile(path.join(ROOT, p));
});

// Vulnerable: resolve alone does not confine.
app.get('/resolve', (req, res) => {
  const p = path.resolve(ROOT, req.query.f);
  res.sendFile(p);
});

// Safe: basename keeps only the final component.
app.get('/basename', (req, res) => {
  const f = path.basename(req.query.f);
  res.sendFile(path.join(ROOT, f));
});

// Safe: the same through a synchronous read.
app.get('/basename-sync', (req, res) => {
  const name = path.basename(req.query.name);
  res.end(fs.readFileSync(path.join('/var/uploads', name)));
});
