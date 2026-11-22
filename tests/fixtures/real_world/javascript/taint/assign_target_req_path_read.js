const express = require('express');
const app = express();

app.get('/echo', function (req, res) {
  res.send('<p>' + req.path + '</p>');
});
