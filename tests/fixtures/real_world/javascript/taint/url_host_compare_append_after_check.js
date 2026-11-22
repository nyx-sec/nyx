// The host check covers the parsed string, not text appended to it afterwards.
const express = require('express');
const app = express();

app.get('/g', async (req, res) => {
  const raw = req.query.u;
  const u = new URL(raw);
  if (u.host === 'a.com') {
    const x = raw + '@evil.com';
    await fetch(x);
  }
  res.end();
});
