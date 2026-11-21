// A leading-slash check alone is not an open-redirect guard: `//evil.example`
// and `/\evil.example` both start with `/` and browsers follow them off-site.
const express = require('express');
const app = express();

app.get('/login', (req, res) => {
  const next = req.query.next;
  if (!next.startsWith('/')) {
    return res.redirect('/');
  }
  res.redirect(next);
});
