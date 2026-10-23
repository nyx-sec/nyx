// The try body only assigns another constant, so the handler never sees
// request data.
const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/run', (req, res) => {
  let cmd = 'ls';
  if (req.query.verbose) {
    console.log('verbose');
  }
  try {
    cmd = 'pwd';
    doSomething();
  } catch (e) {
    exec(cmd);
  }
  res.send('done');
});
