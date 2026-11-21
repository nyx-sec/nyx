var exec = require('child_process').exec;
var BIN = "/usr/bin/uptime";

function runTainted(req, db) {
    var obj = { safeField: "SELECT 1", unsafeField: req.query.cmd };
    return db.query(obj.unsafeField);
}

function runConst(req, db) {
    var obj = { safeField: "SELECT 1", unsafeField: req.query.cmd };
    return db.query(obj.safeField);
}

function runNestedConst(req) {
    var cfg = { auth: { user: req.query.name, template: "/usr/bin/whoami" } };
    exec(cfg.auth.template);
}

function runIdentConst(req) {
    var job = { bin: BIN, arg: req.query.a };
    exec(job.bin);
}

function runSpread(req) {
    var opts = { ...req.body, safe: "x" };
    exec(opts.cmd);
}

module.exports = { runTainted, runConst, runNestedConst, runIdentConst, runSpread };
