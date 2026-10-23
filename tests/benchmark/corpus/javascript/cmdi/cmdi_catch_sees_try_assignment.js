// The handler runs after the try body assigned `cmd`; an earlier branch puts
// the try body in a later basic block than the default value.
const { exec } = require('child_process');
const express = require('express');
const app = express();

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
