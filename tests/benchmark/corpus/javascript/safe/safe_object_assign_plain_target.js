const express = require('express');
const app = express();

// A shallow Object.assign into a plain object cannot reach Object.prototype.
app.post('/settings', (req, res) => {
    Object.assign({}, { limit: 10 }, req.body);
    res.status(204).end();
});
