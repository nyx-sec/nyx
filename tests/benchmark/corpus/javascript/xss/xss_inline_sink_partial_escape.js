const express = require('express');
const escapeHtml = require('escape-html');
const app = express();

app.get('/card', (req, res) => {
  res.send('<h2>' + escapeHtml(req.query.title) + '</h2><div>' + req.query.body + '</div>');
});
