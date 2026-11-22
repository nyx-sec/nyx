const express = require('express');
const app = express();
const FILES_DIR = '/srv/files';

app.get('/files/*file', function (req, res, next) {
  res.download(req.params.file.join('/'), { root: FILES_DIR }, function (err) {
    if (err) next(err);
  });
});
