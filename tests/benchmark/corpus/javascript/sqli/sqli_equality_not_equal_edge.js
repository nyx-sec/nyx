const express = require('express');
const mysql = require('mysql');

const db = mysql.createConnection({});
const app = express();

app.get('/list', (req, res) => {
  const dir = req.query.dir;
  if (dir !== 'asc') {
    db.query('SELECT * FROM t ORDER BY id ' + dir, (e, rows) => res.json(rows));
  }
});
