const express = require('express');
const cp = require('child_process');
const app = express();

function withName(obj, name) {
  obj.name = name;
  return obj;
}

app.get('/run', (req, res) => {
  const job = withName({}, req.query.job);
  cp.exec(job.name);
  res.send('ok');
});
