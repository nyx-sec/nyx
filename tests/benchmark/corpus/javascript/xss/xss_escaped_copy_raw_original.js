const express = require('express');
const escapeHtml = require('escape-html');
const app = express();

app.get('/greet', (req, res) => {
  let name = req.query.name;
  let shown = name;
  shown = escapeHtml(shown);
  console.log(shown);
  res.send('<p>' + name + '</p>');
});
