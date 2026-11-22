// Each handler declares its own leaked, so nothing is shared between them.
var express = require('express');
var app = express();

app.get('/set', function (req, res) {
  var leaked = req.query.a;
  res.end('ok');
});

app.get('/show', function (req, res) {
  var leaked = 'static';
  res.send(leaked);
});
