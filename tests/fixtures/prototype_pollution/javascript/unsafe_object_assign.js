// Unsafe: Object.assign into a shared prototype with attacker-controlled
// `req.body`.  Every `Session` instance inherits the injected properties.
function Session() {}

function handler(req, res) {
    Object.assign(Session.prototype, req.body);
    res.json({ ok: true });
}

module.exports = handler;
