// A bare "/" prefix is not a same-origin lock: `next=/evil.example` makes the
// target `//evil.example`.
const express = require('express');
const app = express();

app.get('/go', (req, res) => {
  res.redirect('/' + req.query.next);
});
