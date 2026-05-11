// Safe: req.query.lang routed through the project-local `stripCRLF` helper
// (a registered HEADER_INJECTION sanitizer) before the subscript-set, so
// taint-header-injection stays clean.
function stripCRLF(raw) {
    return raw.replace(/[\r\n]/g, '');
}

function handler(req, res) {
    const lang = req.query.lang;
    res.headers["X-Forwarded-By"] = stripCRLF(lang);
    res.end();
}

module.exports = handler;
