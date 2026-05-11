// Safe: req.query.lang routed through the project-local `stripCRLF` helper
// before being written to the response header.
function stripCRLF(raw) {
    return raw.replace(/[\r\n]/g, '');
}

function handler(req, res) {
    const lang = req.query.lang;
    const safe = stripCRLF(lang);
    res.setHeader('X-Lang', safe);
    res.end();
}

module.exports = handler;
