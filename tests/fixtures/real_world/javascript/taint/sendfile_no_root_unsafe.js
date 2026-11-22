const express = require('express');
const app = express();

app.get('/files/*file', function (req, res, next) {
  res.download(req.params.file.join('/'), function (err) {
    if (err) next(err);
  });
});

app.get('/assets/:name', function (req, res) {
  res.sendFile(req.params.name, { headers: { 'x-sent': 'true' } });
});

app.get('/open/:name', function (req, res) {
  const opts = { maxAge: 1000 };
  res.sendFile(req.params.name, { ...opts, root: process.env.ROOT });
});
