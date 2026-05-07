// Safe: `set-value` invoked with constant key + literal value.  No tainted
// flow into the path or value position, no PROTOTYPE_POLLUTION.
const setValue = require('set-value');

function handler(req, res) {
    const target = {};
    setValue(target, "name", "alice");
    res.json(target);
}

module.exports = handler;
