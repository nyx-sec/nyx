// A tainted container keeps its taint through an element read, and the key
// itself is still tainted when it is echoed.
var express = require('express');
var app = express();

app.get('/echo', function (req, res) {
  var name = req.params.name;
  res.send('<h1>' + name);
});

app.get('/body', function (req, res) {
  var data = JSON.parse(req.body.raw);
  var k = req.query.k;
  var item = data[k];
  res.send(item);
});
