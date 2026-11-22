var express = require('express');
var app = express();

function processAndStore(input) {
    var client = require('pg').Client();
    client.query("INSERT INTO log VALUES ('" + input + "')");
    return input.length;
}

app.get('/log', function(req, res) {
    var count = processAndStore(req.query.msg);
    res.send(String(count));
});
