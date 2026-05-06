// Phase 09: tainted *key* in `obj[key] = val` is the prototype-pollution
// channel.  When `req.query.k` resolves to `__proto__` / `constructor`, the
// assignment mutates `Object.prototype` globally.
function handler(req, res) {
    const target = {};
    const userKey = req.query.k;
    target[userKey] = req.query.v;
    res.json(target);
}

module.exports = handler;
