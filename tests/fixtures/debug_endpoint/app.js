const express = require('express');
const app = express();

// Debug endpoint that leaks environment variables
app.get('/debug', (req, res) => {
  const env = process.env;
  res.send(env.DATABASE_URL);
});

// Another endpoint leaking query params via tainted flow
app.get('/echo', (req, res) => {
  const input = req.query.data;
  res.send(input);
});
