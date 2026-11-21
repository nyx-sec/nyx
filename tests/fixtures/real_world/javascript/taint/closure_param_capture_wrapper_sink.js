// The timer closure captures the wrapper's parameter and execs it, so the
// request value reaches the exec through the call to `schedule`.
// Expected: a flow reported at the call site of `schedule`.
var express = require('express');
var cp = require('child_process');
var app = express();

function schedule(label) {
    console.log('scheduling', label);
    setTimeout(function () {
        cp.exec(label);
    }, 1000);
}

app.get('/job', function (req, res) {
    schedule(req.query.name);
    res.send('queued');
});
