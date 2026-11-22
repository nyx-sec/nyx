const express = require('express');
const app = express();

// Test-style code that writes to request properties. The assignment
// targets are written, not read, so nothing here is attacker input.
function handler(req, res) {
  req.path = '/assets/missing.css';
  res.render('error', { path: 'static' }, function (err, html) {
    res.send(html);
  });
}

function withQuery(req, res) {
  req.query = { token: 'test' };
  res.send('ok');
}

function withHeader(req, res) {
  req.headers['content-length'] = '20';
  res.send('done');
}

app.get('/a', handler);
app.get('/b', withQuery);
app.get('/c', withHeader);
