// An element read out of a tainted container stays tainted.
var express = require('express');
var app = express();

app.get('/body', function (req, res) {
  var data = JSON.parse(req.body.raw);
  var k = req.query.k;
  var item = data[k];
  res.send(item);
});
