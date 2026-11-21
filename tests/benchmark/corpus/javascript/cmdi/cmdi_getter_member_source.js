const express = require('express');
const cp = require('child_process');
const app = express();

function getCommand(req) {
  return req.query.cmd;
}

app.get('/run', (req, res) => {
  const cmd = getCommand(req);
  cp.exec(cmd);
  res.send('ok');
});
