const express = require('express');
const fs = require('fs');
const app = express();

app.get('/read', (req, res) => {
  const name = req.query.name;
  // Rejects `..` but not absolute paths: `?name=/etc/passwd` still reads.
  if (name.includes('..')) {
    return res.status(400).send('bad');
  }
  fs.readFile(name, (err, data) => res.send(data));
});
