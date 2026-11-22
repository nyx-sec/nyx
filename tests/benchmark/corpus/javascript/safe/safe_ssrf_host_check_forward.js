// The checked string itself is forwarded unchanged after a same-host check.
const express = require('express');
const app = express();

app.get('/g', async (req, res) => {
  const raw = req.query.u;
  const u = new URL(raw);
  if (u.host === 'a.com') {
    await fetch(raw);
  }
  res.end();
});
