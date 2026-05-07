// Unsafe: `set-value` standalone helper (CVE-2019-10747 / CVE-2021-23440)
// invoked with attacker-controlled key and value.  A tainted key of
// `__proto__.polluted` mutates Object.prototype.  Inline `req.body.*`
// member access at the gated arg position must seed taint correctly —
// regression guard for the bare-callee gate-text-derivation fix.
const setValue = require('set-value');

function handler(req, res) {
    const target = {};
    setValue(target, req.body.key, req.body.value);
    res.json(target);
}

module.exports = handler;
