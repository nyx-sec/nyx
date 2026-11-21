const cp = require('child_process');
const express = require('express');
const app = express();

// Every path through the try body returns, and the finally clause still runs.
app.get('/cleanup', (req, res) => {
  try {
    return res.send('ok');
  } finally {
    cp.exec('rm -rf ' + req.query.dir);
  }
});

// Same shape with a constant command: nothing attacker-controlled reaches it.
app.get('/rotate', (req, res) => {
  try {
    return res.send('ok');
  } finally {
    cp.exec('logrotate /etc/app.conf');
  }
});
