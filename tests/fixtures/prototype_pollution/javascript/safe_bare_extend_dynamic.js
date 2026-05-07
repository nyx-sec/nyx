// Safe: bare `extend` invoked with a dynamic flag value at arg 0.  Without
// literal evidence that the deep-merge form is in use, the `LiteralOnly`
// gate suppresses (no conservative ALL_ARGS_PAYLOAD fire).  This avoids
// over-firing on shallow `extend(target, src)` shapes (Underscore-style)
// where arg 0 is the target object, not a deep flag.
const { extend } = require('some-utility');

function handler(req, res) {
    const target = {};
    extend(target, req.body);
    res.json(target);
}

module.exports = handler;
