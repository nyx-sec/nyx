// The timer closure reads its own env var and execs it. `label` is only
// logged, so the request value never reaches the exec.
// Expected: the env -> exec flow inside the closure, and no request flow
// attributed to `schedule(label)` at its call site.
var express = require('express');
var cp = require('child_process');
var app = express();

function schedule(label) {
    console.log('scheduling', label);
    setTimeout(function () {
        var cmd = process.env.CRON_CMD;
        cp.exec(cmd);
    }, 1000);
}

app.get('/job', function (req, res) {
    schedule(req.query.name);
    res.send('queued');
});
