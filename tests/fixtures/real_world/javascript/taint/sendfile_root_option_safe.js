const express = require('express');
const app = express();
const FILES_DIR = '/srv/files';

app.get('/files/*file', function (req, res, next) {
  res.download(req.params.file.join('/'), { root: FILES_DIR }, function (err) {
    if (err) next(err);
  });
});

app.get('/assets/:name', function (req, res) {
  res.sendFile(req.params.name, { root: FILES_DIR });
});
