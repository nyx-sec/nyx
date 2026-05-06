// Phase 09: `Object.create(null)` produces a null-prototype receiver
// that has no `Object.prototype` to mutate, so writes through any key
// (including `__proto__`) cannot pollute the global prototype chain.
function handler(req, res) {
    const target = Object.create(null);
    const userKey = req.query.k;
    target[userKey] = req.query.v;
    res.json(target);
}

module.exports = handler;
