const express = require('express');
const app = express();
app.get('/proxy', async (req, res) => {
    // A fixed `/v1/` head makes the path an absolute-path reference, which
    // keeps the base host whatever follows it.
    const target = new URL('/v1/items/' + req.query.id, 'https://api.example.com');
    const r = await fetch(target);
    res.status(204).end();
});
