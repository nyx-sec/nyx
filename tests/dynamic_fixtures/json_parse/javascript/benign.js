// Phase 11 (Track J.9) — JavaScript JSON_PARSE benign control fixture.
//
// JSON.parse then deep-merge into a `Object.create(null)` target, the
// canonical mitigation; the prototype-less target cannot reach
// `Object.prototype` so the canary never fires.
function run(value) {
    const parsed = JSON.parse(value);
    const target = Object.create(null);
    for (const k of Object.keys(parsed)) {
        if (k === '__proto__' || k === 'constructor') continue;
        target[k] = parsed[k];
    }
    return target;
}

module.exports = { run };
