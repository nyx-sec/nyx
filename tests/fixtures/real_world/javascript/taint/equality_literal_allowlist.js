const express = require('express');
const mysql = require('mysql');
const db = mysql.createConnection({});
const app = express();

// Safe: the query only runs when dir is one of two literals.
app.get('/a', (req, res) => {
  const dir = req.query.dir;
  if (dir === 'asc' || dir === 'desc') {
    db.query('SELECT * FROM t ORDER BY id ' + dir, (e, r) => res.json(r));
  }
});

// Safe: anything but the two literals returns early.
app.get('/b', (req, res) => {
  const dir = req.query.dir;
  if (dir !== 'asc' && dir !== 'desc') {
    return res.status(400).end();
  }
  db.query('SELECT * FROM t ORDER BY id ' + dir, (e, r) => res.json(r));
});

// Vulnerable: the sink is on the not-equal edge.
app.get('/c', (req, res) => {
  const dir = req.query.dir;
  if (dir !== 'asc') {
    db.query('SELECT * FROM t ORDER BY id ' + dir, (e, r) => res.json(r));
  }
});

// Vulnerable: the comparison only guards the logging branch.
app.get('/d', (req, res) => {
  const dir = req.query.dir;
  if (dir === 'asc') {
    console.log('ascending');
  }
  db.query('SELECT * FROM t ORDER BY id ' + dir, (e, r) => res.json(r));
});

// Vulnerable: the second disjunct does not pin dir.
app.get('/e', (req, res) => {
  const dir = req.query.dir;
  const flag = req.query.flag;
  if (dir === 'asc' || flag) {
    db.query('SELECT * FROM t ORDER BY id ' + dir, (e, r) => res.json(r));
  }
});
