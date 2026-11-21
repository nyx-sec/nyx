const { exec } = require('child_process');
const express = require('express');
const app = express();

// The handler runs after the try body assigned `cmd`, even though an earlier
// branch puts the try body in a later basic block than the default.
app.get('/run', (req, res) => {
  let cmd = 'ls';
  if (req.query.verbose) {
    console.log('verbose');
  }
  try {
    cmd = req.query.cmd;
    doSomething();
  } catch (e) {
    exec(cmd);
  }
  res.send('done');
});

// Same shape, but the try body only assigns another constant.
app.get('/fixed', (req, res) => {
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
