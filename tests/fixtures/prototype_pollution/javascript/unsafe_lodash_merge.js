// Unsafe: lodash `_.merge` invoked with attacker-controlled `req.body` as
// the source argument.  Tainted `__proto__` / `constructor` keys can rewrite
// Object.prototype globally.  PROTOTYPE_POLLUTION fires.
const _ = require('lodash');

function handler(req, res) {
    const target = {};
    _.merge(target, req.body);
    res.json(target);
}

module.exports = handler;
