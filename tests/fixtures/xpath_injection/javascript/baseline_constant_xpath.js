// Baseline: expression is a compile-time constant.  No taint reaches
// xpath.select so no XPATH_INJECTION finding fires.
const xpath = require('xpath');
const { DOMParser } = require('xmldom');

function lookup(req, res) {
    const doc = new DOMParser().parseFromString('<root/>');
    const nodes = xpath.select("//user[@role='admin']", doc);
    res.json(nodes);
}

module.exports = lookup;
