const express = require('express');
const { execSync } = require('child_process');

const app = express();

app.get('/run', (req, res) => {
  const cmd = req.query.cmd;
  switch (execSync(cmd).toString().trim()) {
    case 'ok':
      res.send('done');
      break;
    default:
      res.send('failed');
  }
});
