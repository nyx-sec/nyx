const fs = require('fs');
const express = require('express');
const app = express();

// Request data is the file content; the path is fixed.
app.post('/feedback', (req, res) => {
    fs.writeFileSync('/var/log/feedback.json', JSON.stringify(req.body));
    res.status(204).end();
});
