const express = require('express');
const { exec } = require('child_process');
const db = require('./db');
const app = express();
const SORTS = ['name', 'date'];

function isValidHost(h) { return /^[a-z.]+$/.test(h); }
function normalize(h) { return h.toLowerCase(); }

app.get('/reread', (req, res) => {
  let host = req.query.host;
  if (!isValidHost(host)) return res.status(400).send('bad');
  host = req.query.other;
  exec('ping ' + host);
});

app.get('/append-source', (req, res) => {
  let host = req.query.host;
  if (!isValidHost(host)) return res.status(400).send('bad');
  host = host + req.query.extra;
  exec('ping ' + host);
});

app.get('/append-local', (req, res) => {
  let host = req.query.host;
  const extra = req.query.extra;
  if (!isValidHost(host)) return res.status(400).send('bad');
  host = host + extra;
  exec('ping ' + host);
});

app.get('/trim', (req, res) => {
  let host = req.query.host;
  if (!isValidHost(host)) return res.status(400).send('bad');
  host = host.trim().toLowerCase();
  exec('ping ' + host);
});

app.get('/normalize', (req, res) => {
  let host = req.query.host;
  if (!isValidHost(host)) return res.status(400).send('bad');
  host = normalize(host);
  exec('ping ' + host);
});

app.get('/suffix', (req, res) => {
  let host = req.query.host;
  if (!isValidHost(host)) return res.status(400).send('bad');
  host = host + '.internal';
  exec('ping ' + host);
});

app.get('/items', (req, res) => {
  const sort = req.query.sort;
  if (!SORTS.includes(sort)) return res.status(400).end();
  const sql = 'SELECT * FROM items ORDER BY ' + sort + ' LIMIT ' + req.query.limit;
  db.query(sql);
});

app.get('/items-fixed', (req, res) => {
  const sort = req.query.sort;
  if (!SORTS.includes(sort)) return res.status(400).end();
  const sql = 'SELECT * FROM items ORDER BY ' + sort + ' LIMIT 10';
  db.query(sql);
});
