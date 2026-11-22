const express = require('express');

const app = express();

// res.json sends Content-Type application/json, not HTML.
app.get('/echo', (req, res) => {
  const data = req.query.data;
  res.json({ data: data });
});

app.get('/raw', (req, res) => {
  res.json(req.query);
});

module.exports = app;
