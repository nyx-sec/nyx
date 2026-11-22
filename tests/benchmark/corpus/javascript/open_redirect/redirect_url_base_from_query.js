const express = require('express');
const app = express();

app.get('/go', (req, res) => {
  const u = new URL(req.query.next);
  u.searchParams.append('a', 'b');
  return res.redirect(302, u.href);
});
