const express = require('express');
const fs = require('fs');
const app = express();

app.get('/read', (req, res) => {
  let name = req.query.a;
  if (name.includes('..')) {
    return res.status(400).send('bad');
  }
  // A fresh value: the `..` check above says nothing about it.
  name = req.query.b;
  if (name.startsWith('/')) {
    return res.status(400).send('bad');
  }
  const data = fs.readFileSync(name);
  res.end('ok');
});
