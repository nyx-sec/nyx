// The key of a lookup picks an element; a request-supplied key does not
// make the element request data.
var express = require('express');
var app = express();
var repos = { tobi: ['a', 'b'], loki: ['c'] };

app.get('/api/user/:name/repos', function (req, res, next) {
  var name = req.params.name;
  var user = repos[name];
  if (user) res.send(user);
  else next();
});
