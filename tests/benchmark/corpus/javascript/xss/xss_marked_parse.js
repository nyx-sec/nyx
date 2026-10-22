const express = require('express');
const { marked } = require('marked');
const app = express();

app.post('/preview', (req, res) => {
    const md = req.body.markdown;
    const html = marked.parse(md);
    res.send(html);
});
