// Unsafe: Object.assign with attacker-controlled `req.body` source.
function handler(req, res) {
    const target = {};
    Object.assign(target, req.body);
    res.json(target);
}

module.exports = handler;
