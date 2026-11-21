// Counterpart to safe/safe_pg_named_query_const.js: the user value is part
// of the query text itself, so the bind array does not help.
const express = require('express');
const { Pool } = require('pg');

const pool = new Pool();
const app = express();

app.get('/u', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users WHERE email = ' + req.query.email, []);
  res.json(rows);
});
