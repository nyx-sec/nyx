const express = require('express');
const db = require('./db');
const app = express();
const SORTABLE = ['name', 'created_at'];

// Safe: the allowlisted value is copied into another variable on one arm,
// a literal on the other.
app.get('/a', async (req, res) => {
  const s = req.query.sort;
  let order;
  if (SORTABLE.includes(s)) {
    order = s;
  } else {
    order = 'name';
  }
  await db.query(`SELECT * FROM users ORDER BY ${order}`);
});

// Safe: the same choice as a conditional expression.
app.get('/b', async (req, res) => {
  const s = req.query.sort;
  const order = SORTABLE.includes(s) ? s : 'name';
  await db.query(`SELECT * FROM users ORDER BY ${order}`);
});

// Vulnerable: the request value is taken on the not-allowlisted arm.
app.get('/c', async (req, res) => {
  const s = req.query.sort;
  const order = SORTABLE.includes(s) ? 'name' : s;
  await db.query(`SELECT * FROM users ORDER BY ${order}`);
});
