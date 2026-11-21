// The try body returns, and the finally clause still runs: the cleanup
// command is built from the request.
const cp = require('child_process');
const express = require('express');
const app = express();

app.get('/cleanup', (req, res) => {
  try {
    return res.send('ok');
  } finally {
    cp.exec('rm -rf ' + req.query.dir);
  }
});
