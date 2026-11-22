// An undeclared (implicit global) variable written in one handler and read
// in another is a sloppy-mode global and keeps its taint.
var express = require('express');
var app = express();

app.get('/set', function (req, res) {
  leaked = req.query.a;
  res.end('ok');
});

app.get('/show', function (req, res) {
  res.send(leaked);
});
