const express = require('express');
const fs = require('fs');
const app = express();

app.get('/read', (req, res) => {
  const name = req.query.name;
  // Rejecting both `..` and absolute paths leaves a relative, `..`-free path.
  if (name.includes('..') || name.startsWith('/')) {
    return res.status(400).send('bad');
  }
  fs.readFile(name, (err, data) => res.end('ok'));
});
