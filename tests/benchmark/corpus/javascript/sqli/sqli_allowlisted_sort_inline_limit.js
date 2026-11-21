const express = require('express');
const db = require('./db');
const app = express();
const SORTS = ['name', 'date'];

app.get('/items', (req, res) => {
  const sort = req.query.sort;
  if (!SORTS.includes(sort)) return res.status(400).end();
  const sql = 'SELECT * FROM items ORDER BY ' + sort + ' LIMIT ' + req.query.limit;
  db.query(sql, (err, rows) => res.json(rows));
});
