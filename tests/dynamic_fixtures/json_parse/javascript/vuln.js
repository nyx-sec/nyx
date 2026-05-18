// Phase 11 (Track J.9) — JavaScript JSON_PARSE vuln fixture.
//
// JSON.parse the attacker bytes then naive deep-merge into a vanilla
// target object.  A `__proto__` key walks into `Object.prototype` and
// trips the canary trap.
function run(value) {
    const parsed = JSON.parse(value);
    const target = {};
    deepMerge(target, parsed);
    return target;
}

function deepMerge(t, s) {
    for (const k of Object.keys(s)) {
        if (s[k] !== null && typeof s[k] === 'object') {
            if (typeof t[k] !== 'object' || t[k] === null) t[k] = {};
            deepMerge(t[k], s[k]);
        } else {
            t[k] = s[k];
        }
    }
}

module.exports = { run };
