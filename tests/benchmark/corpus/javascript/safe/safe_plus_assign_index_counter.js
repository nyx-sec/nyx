// Counting by an attacker-chosen key with `+=` updates an existing slot;
// it cannot replace Object.prototype, so it is not prototype pollution.
const express = require('express');
const app = express();
app.get('/count', (req, res) => {
    const counts = {};
    counts[req.query.word] += 1;
    res.json({ total: Object.keys(counts).length });
});
