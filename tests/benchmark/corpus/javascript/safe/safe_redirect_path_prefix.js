// The redirect target starts with a fixed same-origin path, so the request
// value only picks a path below /users/.
const express = require('express');
const app = express();

app.get('/u/:id', (req, res) => {
  res.redirect(`/users/${req.params.id}`);
});

app.get('/v/:id', (req, res) => {
  res.redirect(301, '/users/' + req.params.id);
});
