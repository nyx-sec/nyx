var express = require('express');
var DOMPurify = require('dompurify');
var app = express();

app.get('/greet', function(req, res) {
    res.send(DOMPurify.sanitize(req.query.name));
});
