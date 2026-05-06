// Phase 09: reject-list guard suppresses prototype pollution.  The
// dangerous-key path terminates with `return`, so the assignment that
// follows only runs when `userKey` is provably not `__proto__` /
// `constructor` / `prototype`.
function handler(req, res) {
    const target = {};
    const userKey = req.query.k;
    if (userKey === "__proto__" || userKey === "constructor" || userKey === "prototype") {
        return;
    }
    target[userKey] = req.query.v;
    res.json(target);
}

module.exports = handler;
