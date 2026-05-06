// Unsafe: npm `xpath` package's `select` receives an expression assembled
// from req.query.  XPATH_INJECTION fires on the expression argument.
const xpath = require('xpath');
const { DOMParser } = require('xmldom');

function lookup(req, res) {
    const doc = new DOMParser().parseFromString('<root/>');
    const user = req.query.user;
    const expr = "//user[name='" + user + "']";
    const nodes = xpath.select(expr, doc);
    res.json(nodes);
}

module.exports = lookup;
