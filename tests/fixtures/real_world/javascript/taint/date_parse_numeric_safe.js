var express = require('express');
var exec = require('child_process').exec;
var app = express();

app.post('/touch', function(req, res) {
    var ts = Date.parse(req.body.when);
    exec("touch -d @" + ts + " stamp");
    res.send("ok");
});
