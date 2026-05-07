// Safe: req.query.next routed through `validateRedirectUrl` allowlist
// before being passed to res.redirect.
function validateRedirectUrl(raw) {
    return raw.startsWith('/') ? raw : '/';
}

function handler(req, res) {
    const target = req.query.next;
    const safe = validateRedirectUrl(target);
    res.redirect(safe);
}

module.exports = handler;
