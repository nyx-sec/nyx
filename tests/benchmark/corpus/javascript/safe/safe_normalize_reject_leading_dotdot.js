const express = require('express');
const path = require('path');
const app = express();
const ROOT = '/srv/files';

app.get('/download', (req, res) => {
  const clean = path.normalize(req.query.f);
  if (clean.startsWith('..') || path.isAbsolute(clean)) {
    return res.status(400).end();
  }
  res.sendFile(path.join(ROOT, clean));
});
