var express = require('express');
var app = express();

app.get('/proxy', async function(req, res) {
    var target = req.query.host;
    var url = 'https://' + target;
    var response = await fetch(url);
    res.send('done');
});
