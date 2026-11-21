// Safe: Object.assign copies own properties with plain [[Set]] and does not
// recurse.  A `__proto__` key in `req.body` only replaces `target`'s own
// prototype, so `Object.prototype` is never written.
function handler(req, res) {
    const target = {};
    Object.assign(target, req.body);
    res.json(target);
}

module.exports = handler;
