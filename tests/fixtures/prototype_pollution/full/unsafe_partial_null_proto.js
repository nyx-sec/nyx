// Phase 09 flow-sensitive null-prototype guard.  `target` is only
// initialised with `Object.create(null)` on one branch; the else branch
// leaves it as a plain object whose prototype chain is mutable.  The
// prior AST-scan suppressor matched any same-function `Object.create(null)`
// assignment and silenced both branches; the SSA TypeFacts path joins
// to Unknown at the phi and keeps PROTOTYPE_POLLUTION on the unsafe path.
function handler(req, res) {
    let target;
    if (req.query.safe) {
        target = Object.create(null);
    } else {
        target = {};
    }
    const userKey = req.query.k;
    target[userKey] = req.query.v;
    res.json(target);
}

module.exports = handler;
