var express = require('express');
var exec = require('child_process').exec;
var app = express();

app.post('/ls', function(req, res) {
    var body = req.body;
    exec("ls " + body.dir);
});

app.get('/hello', function(req, res) {
    var q = req.query;
    res.send("<h1>Hello " + q.name + "</h1>");
});

app.post('/run', function(req, res) {
    var job = JSON.parse(req.body.payload);
    exec(job.command);
});
