var express = require('express');
var { forward } = require('./helper');

var app = express();

// Tainted URL, fixed body: SSRF must fire on the URL flow.  DATA_EXFIL
// must NOT fire — the body is a literal string, not a sensitive source,
// and the cap-vs-position split through the wrapper's summary keeps the
// URL's taint from leaking onto the body's gate.
app.get('/proxy', function(req, res) {
    var taintedUrl = req.query.url;
    forward(taintedUrl, '{"ok":true}');
    res.status(204).end();
});
