// HTML accumulated with `+=`: the tainted item is appended to a literal
// prefix and the whole string is sent back unescaped.
const express = require('express');
const app = express();
app.get('/list', (req, res) => {
    let html = '<ul>';
    html += '<li>' + req.query.item + '</li>';
    html += '</ul>';
    res.send(html);
});
