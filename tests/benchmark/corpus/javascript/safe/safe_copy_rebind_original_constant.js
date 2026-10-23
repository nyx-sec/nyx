const express = require('express');
const app = express();
const GREETING = '<p>Hello</p>';

app.get('/greet', (req, res) => {
  let label = GREETING;
  if (req.query.label) {
    label = req.query.label;
  }
  console.log(label.length);
  res.send(GREETING);
});
