const express = require('express');
const app = express();

app.get('/unsub', (req, res) => {
  const redirectUrl = new URL('https://site.example/portal');
  redirectUrl.searchParams.append('uuid', req.query.uuid);
  redirectUrl.searchParams.append('action', 'unsubscribe');
  return res.redirect(302, redirectUrl.href);
});
