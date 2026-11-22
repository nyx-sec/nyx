const express = require('express');
const app = express();

app.get('/files/*file', function (req, res, next) {
  res.download(req.params.file.join('/'), { root: '/srv/files' }, function (err) {
    if (err) next(err);
  });
});

app.get('/assets/:name', function (req, res) {
  res.sendFile(req.params.name, { root: '/srv/files' });
});
