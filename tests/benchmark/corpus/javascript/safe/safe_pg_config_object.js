const express = require('express');
const { Pool } = require('pg');

const pool = new Pool();
const app = express();

// Config-object form: the request value is a bind value, not SQL text.
app.get('/user', async (req, res) => {
    const result = await pool.query({
        text: 'SELECT * FROM users WHERE id = $1',
        values: [req.query.id],
    });
    res.json(result.rows);
});
