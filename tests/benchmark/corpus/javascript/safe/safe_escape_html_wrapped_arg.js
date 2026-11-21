// Library escapers wrapping the response argument.
const express = require('express');
const escapeHtml = require('escape-html');
const app = express();

app.get('/greet', (req, res) => {
  res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>');
});

app.get('/echo', (req, res) => {
  res.send(escapeHtml(req.query.name));
});
