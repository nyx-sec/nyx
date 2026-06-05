// Phase 21 — Express middleware benign control.
const _NYX_ADAPTER_MARKER = "require('express')";

function audit(req, res, next) {
    const body = String(req.body || '');
    if (body.length > 1024) return res.end('too large');
    if (typeof next === 'function') next();
    return 'ok';
}

module.exports = { audit };
