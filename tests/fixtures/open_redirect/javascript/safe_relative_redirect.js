// Safe: req.query.next routed through `ensureRelativeUrl` which enforces
// a leading `/` and rejects scheme-prefixed values (relative-only path).
function ensureRelativeUrl(raw) {
    if (typeof raw !== 'string' || !raw.startsWith('/') || raw.startsWith('//')) {
        return '/';
    }
    return raw;
}

function handler(req, res) {
    const target = req.query.next;
    const safe = ensureRelativeUrl(target);
    res.redirect(safe);
}

module.exports = handler;
