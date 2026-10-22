import express from 'express';
import * as path from 'path';
import { readFileSync, createReadStream, writeFileSync, renameSync } from 'node:fs';
import fs from 'fs';

const app = express();

app.get('/read', (req, res) => {
  const p = path.join('/data', req.query.f as string);
  readFileSync(p);
  res.end();
});

app.get('/stream', (req, res) => {
  createReadStream(req.params.f).pipe(res);
});

app.post('/move', (req, res) => {
  renameSync('/tmp/upload', req.body.dest);
  res.end();
});

app.post('/append', (req, res) => {
  fs.appendFileSync(req.body.logName, 'entry\n');
  res.end();
});

app.post('/mkdir', (req, res) => {
  fs.mkdirSync(req.body.dir);
  res.end();
});

// Safe: request data is the file content, the path is fixed.
app.post('/save', (req, res) => {
  writeFileSync('/var/app/last-message.txt', req.body.message);
  fs.appendFileSync('/var/app/audit.log', req.body.message);
  res.end();
});
