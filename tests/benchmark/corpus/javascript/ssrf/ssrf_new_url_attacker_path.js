const express = require('express');
const app = express();
app.get('/proxy', async (req, res) => {
    const path = req.query.path;
    // An absolute or protocol-relative path replaces the base's host.
    const target = new URL(path, 'https://api.example.com');
    const r = await fetch(target);
    res.status(204).end();
});
