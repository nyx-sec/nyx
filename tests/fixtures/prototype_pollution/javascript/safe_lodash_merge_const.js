// Safe: lodash `_.merge` invoked with a constant-source object.  No taint
// reaches the merge so PROTOTYPE_POLLUTION does not fire.
const _ = require('lodash');

function build() {
    const target = {};
    _.merge(target, { a: 1, b: 2 });
    return target;
}

module.exports = build;
