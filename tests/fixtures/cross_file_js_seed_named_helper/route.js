const express = require('express');
const { deploy, status } = require('./lib');
const app = express();

app.post('/deploy', (req, res) => {
  const target = req.body.target;
  deploy(target);
  res.send('ok');
});

app.get('/status', (req, res) => {
  status('all');
  res.send('ok');
});
