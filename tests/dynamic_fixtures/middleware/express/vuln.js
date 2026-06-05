// Phase 21 (Track M.3) — Express middleware vuln fixture.
//
// `audit(req, res, next)` is mounted via `app.use(audit)`.  It splices
// the request body into a shell command via `execSync`.
const _NYX_ADAPTER_MARKER = "require('express')";
const _NYX_REGISTER_MARKER = "app.use(audit)";

const { execSync } = require('child_process');

function audit(req, res, next) {
    // SINK: tainted req.body concatenated into shell command.
    const out = execSync('echo ' + String(req.body || '')).toString();
    if (typeof next === 'function') next();
    return out;
}

module.exports = { audit };
