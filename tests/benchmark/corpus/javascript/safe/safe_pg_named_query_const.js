// The SQL text is a module-level constant; the user value only travels in
// the bind array, which pg sends separately from the query text.
const express = require('express');
const { Pool } = require('pg');

const pool = new Pool();
const app = express();
const FIND_USER = 'SELECT * FROM users WHERE email = $1 AND active = $2';

app.get('/u', async (req, res) => {
  const { rows } = await pool.query(FIND_USER, [req.query.email, true]);
  res.status(rows.length ? 200 : 404).end();
});

app.get('/v', async (req, res) => {
  const sql = 'SELECT * FROM users WHERE email = $1';
  const { rows } = await pool.query(sql, [req.query.email]);
  res.status(rows.length ? 200 : 404).end();
});
