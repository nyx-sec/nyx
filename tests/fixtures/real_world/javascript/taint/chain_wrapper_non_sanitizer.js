var express = require('express');
var app = express();

app.get('/greet', function(req, res) {
    res.send(String(req.query.name));
});

function exclaim(s) {
    return s + '!';
}

app.get('/shout', function(req, res) {
    res.send(exclaim(req.query.name));
});
