// Unsafe: jQuery's deep-merge `extend` imported as a bound name.  Bare
// `extend(true, target, src)` with attacker-controlled `req.body` as a
// source argument can rewrite `Object.prototype` via `__proto__` keys in
// the merged input.  PROTOTYPE_POLLUTION fires via the `LiteralOnly` gate
// keyed on the literal `true` deep-flag at arg 0.
const { extend } = require('jquery');

function handler(req, res) {
    const target = {};
    extend(true, target, req.body);
    res.json(target);
}

module.exports = handler;
