const express = require('express');
const escapeHtml = require('escape-html');
const app = express();

app.get('/profile', (req, res) => {
  const name = req.query.name;
  const bio = req.query.bio;
  const html = '<h1>' + escapeHtml(name) + '</h1><p>' + escapeHtml(bio) + '</p>';
  res.send(html);
});
