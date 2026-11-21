const fs = require('fs');
const express = require('express');
const app = express();

// The request chooses the file that is written.
app.post('/save', (req, res) => {
    fs.writeFileSync(req.query.file, 'saved');
    res.status(204).end();
});
