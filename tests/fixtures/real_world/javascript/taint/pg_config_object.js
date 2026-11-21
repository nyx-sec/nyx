const express = require('express');
const { Pool } = require('pg');
const mysql = require('mysql2');
const pool = new Pool();
const connection = mysql.createConnection({});
const app = express();

app.get('/a', async (req, res) => {
  await pool.query({ text: 'SELECT * FROM t WHERE id = $1', values: [req.query.id] });
  await connection.query({ sql: 'SELECT * FROM t WHERE id = ?', values: [req.query.id] });
  res.status(200).end();
});

app.get('/b', async (req, res) => {
  await pool.query({ text: 'SELECT * FROM t WHERE id = ' + req.query.id });
  res.status(200).end();
});

app.get('/c', async (req, res) => {
  const result = await pool.query({
    text: 'SELECT * FROM t WHERE id = $1',
    values: [req.query.id],
  });
  res.json(result.rows);
});

module.exports = app;
