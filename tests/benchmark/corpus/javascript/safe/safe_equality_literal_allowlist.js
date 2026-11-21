const express = require('express');
const db = require('./db');

const app = express();

app.get('/list', (req, res) => {
  const dir = req.query.dir;
  if (dir !== 'asc' && dir !== 'desc') {
    return res.status(400).end();
  }
  db.query('SELECT * FROM t ORDER BY id ' + dir, (e, rows) => res.json(rows));
});
