// Unsafe: Express `res.setHeader` receives a value built from req.query.
// HEADER_INJECTION fires on the value argument.
function handler(req, res) {
    const lang = req.query.lang;
    res.setHeader('X-Lang', lang);
    res.end();
}

module.exports = handler;
