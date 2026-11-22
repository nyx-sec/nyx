// A module-level variable written in one handler and read in another still
// carries taint, and so does a captured local of an enclosing handler.
var express = require('express');
var app = express();
var shared;

app.get('/set', function (req, res) {
  shared = req.query.a;
  res.end('ok');
});

app.get('/show', function (req, res) {
  res.send(shared);
});
