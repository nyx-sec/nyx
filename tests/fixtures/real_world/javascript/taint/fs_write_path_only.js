const fs = require('fs');
const express = require('express');
const app = express();

app.post('/log', (req, res) => {
  fs.writeFile('/tmp/last.json', JSON.stringify(req.body), () => {});
  fs.writeFileSync('/tmp/out.json', req.body.text);
  fs.appendFileSync('/var/log/app.log', req.query.msg);
  res.end();
});

app.post('/save', (req, res) => {
  fs.writeFileSync('/srv/uploads/' + req.query.name, req.body.text);
  fs.promises.writeFile(req.query.path, 'x');
  res.end();
});

module.exports = app;
