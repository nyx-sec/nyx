// Safe: Object.assign with a constant-source object literal.  No taint
// reaches the merge so PROTOTYPE_POLLUTION does not fire.
function build() {
    const target = {};
    Object.assign(target, { x: 1, y: 2 });
    return target;
}

module.exports = build;
