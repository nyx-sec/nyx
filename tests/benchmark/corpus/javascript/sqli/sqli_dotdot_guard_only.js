const express = require('express');
const mysql = require('mysql');
const db = mysql.createConnection({});
const app = express();

app.get('/file', (req, res) => {
  const name = req.query.name;
  // A `..` check is a path-shape test; it does not make `name` safe for SQL.
  if (name.includes('..')) {
    return res.status(400).send('bad');
  }
  db.query("SELECT * FROM files WHERE name = '" + name + "'", (e, rows) => res.json(rows));
});
