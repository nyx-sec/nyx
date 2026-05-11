// Unsafe: `dot-prop` standalone helper (CVE-2020-8116) invoked with an
// attacker-controlled `path`.  Tainted path `__proto__.polluted` walks
// the prototype chain because dot-prop did not block prototype keys.
const dotProp = require('dot-prop');

function handler(req, res) {
    const target = {};
    dotProp.set(target, req.body.path, req.body.value);
    res.json(target);
}

module.exports = handler;
