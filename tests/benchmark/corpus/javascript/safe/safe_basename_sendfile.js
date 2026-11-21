const express = require('express');
const path = require('path');
const app = express();
const ROOT = '/srv/files';

app.get('/download', (req, res) => {
  const leaf = path.basename(req.query.f);
  res.sendFile(path.join(ROOT, leaf));
});
