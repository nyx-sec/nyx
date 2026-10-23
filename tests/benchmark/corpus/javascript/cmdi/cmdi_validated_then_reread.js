const express = require('express');
const { exec } = require('child_process');
const app = express();

function isValidHost(h) { return /^[a-z.]+$/.test(h); }

app.get('/ping', (req, res) => {
  let host = req.query.host;
  if (!isValidHost(host)) return res.status(400).send('bad');
  host = req.query.fallback;
  exec('ping -c 1 ' + host);
  res.send('ok');
});
