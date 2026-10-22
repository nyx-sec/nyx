// The inline relative-URL check also rejects protocol-relative values, so the
// redirect stays on this origin.
const express = require('express');
const app = express();

app.get('/login', (req, res) => {
  const next = req.query.next;
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\')) {
    return res.redirect('/');
  }
  res.redirect(next);
});
