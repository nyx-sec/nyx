const express = require('express');
const app = express();

app.get('/page', (req, res) => {
  const name = req.query.name;
  // Rejecting absolute paths says nothing about HTML metacharacters.
  if (name.startsWith('/')) {
    return res.status(400).send('bad');
  }
  res.send('<h1>' + name + '</h1>');
});
