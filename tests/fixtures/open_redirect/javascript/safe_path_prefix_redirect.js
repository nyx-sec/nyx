// Safe: the redirect target starts with a fixed same-origin path, so the
// user-controlled suffix cannot change the host.
const express = require('express');
const app = express();

app.get('/a/:id', (req, res) => {
  res.redirect(`/users/${req.params.id}`);
});

app.get('/b/:id', (req, res) => {
  res.redirect('/users/' + req.params.id);
});

app.get('/c/:id', (req, res) => {
  res.redirect(301, `/users/${req.params.id}`);
});

app.get('/d/:id', (req, res) => {
  const target = `/users/${req.params.id}`;
  res.redirect(target);
});

module.exports = app;
