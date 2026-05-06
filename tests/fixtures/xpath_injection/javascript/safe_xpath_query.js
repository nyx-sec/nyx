// Safe: user-supplied substring routed through the project-local
// `escapeXpath` helper before concatenation.  The sanitizer clears the
// XPATH_INJECTION cap so the sink does not fire.
const xpath = require('xpath');
const { DOMParser } = require('xmldom');

function escapeXpath(raw) {
    return raw.replace(/'/g, '&apos;').replace(/"/g, '&quot;');
}

function lookup(req, res) {
    const doc = new DOMParser().parseFromString('<root/>');
    const user = req.query.user;
    const safe = escapeXpath(user);
    const expr = "//user[name='" + safe + "']";
    const nodes = xpath.select(expr, doc);
    res.json(nodes);
}

module.exports = lookup;
