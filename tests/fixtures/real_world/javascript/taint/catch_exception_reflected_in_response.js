const express = require('express');
const app = express();

app.get('/parse', function (req, res) {
  try {
    JSON.parse(req.query.data);
  } catch (e) {
    res.send('<h1>Failed: ' + e.message + '</h1>');
  }
});
