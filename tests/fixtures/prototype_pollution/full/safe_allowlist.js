// Phase 09: allowlist guard restricts the key to a known-safe constant
// set on the true arm of the `if`, so the enclosed assignment cannot
// reach `__proto__` / `constructor` even though `userKey` is tainted.
function handler(req, res) {
    const target = {};
    const userKey = req.query.k;
    if (userKey === "name" || userKey === "id") {
        target[userKey] = req.query.v;
    }
    res.json(target);
}

module.exports = handler;
