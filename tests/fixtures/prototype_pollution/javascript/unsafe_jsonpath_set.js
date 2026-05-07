// Unsafe: jsonpath `jp.set(obj, path, value)` invoked with an
// attacker-controlled `path`.  Tainted path with `__proto__` segments
// pollutes the prototype chain.
const jp = require('jsonpath');

function handler(req, res) {
    const target = {};
    jp.set(target, req.body.path, req.body.value);
    res.json(target);
}

module.exports = handler;
