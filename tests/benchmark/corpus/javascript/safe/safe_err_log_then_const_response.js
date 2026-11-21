// The callback logs the error and still answers with a fixed body.  The
// response payload is a literal, so the ignored error cannot reach it.
const express = require('express');
const fs = require('fs');
const app = express();

app.post('/touch', (req, res) => {
  fs.writeFile('/tmp/touched', 'x', (err) => {
    if (err) {
      console.error(err);
    }
    res.send('saved');
  });
});
