const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/run', (req, res) => {
  const id = req.query.id;
  // The anchored digit regex is what makes `id` safe; the typeof check only
  // rejects query-string arrays.
  if (typeof id !== 'string' || !/^[0-9]+$/.test(id)) {
    return res.status(400).send('bad');
  }
  exec('ls ' + id);
  res.send('ok');
});
