var express = require('express');
var escapeHtml = require('escape-html');
var cp = require('child_process');
var app = express();

function siteHeader() { return '<h1>Site</h1>'; }
function sortColumn(s) { if (s === 'name') { return 'name'; } return 'id'; }
function getCmd(req) { var v = req.query.cmd; return v; }
function card(title, body) { return '<h2>' + escapeHtml(title) + '</h2>' + body; }

app.get('/partial', function (req, res) {
    var bio = req.query.bio; var html = '<p>' + escapeHtml(req.query.name) + '</p>' + bio;
    res.send(html);
});

app.get('/escaped', function (req, res) {
    var html = '<p>' + escapeHtml(req.query.name) + '</p>' + escapeHtml(req.query.bio);
    res.send(html);
});

app.get('/inline', function (req, res) {
    var bio = req.query.bio;
    res.send('<h1>' + escapeHtml('Profile') + '</h1>' + bio);
});

app.get('/sibling', function (req, res) {
    var bio = req.query.bio;
    var html = siteHeader() + bio;
    res.send(html);
});

app.get('/sort', function (req, res) {
    cp.exec('ls --sort=' + sortColumn(req.query.sort));
});

app.get('/run', function (req, res) {
    cp.exec(getCmd(req));
});

app.get('/card-body', function (req, res) {
    var b = req.query.b;
    res.send(card('static', b));
});

app.get('/card-title', function (req, res) {
    var t = req.query.t;
    res.send(card(t, 'static'));
});
