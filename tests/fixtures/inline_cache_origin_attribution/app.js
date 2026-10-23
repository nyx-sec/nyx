// Regression fixture: two call sites to the same helper function,
// each followed by its own downstream sink.  Both argument chains carry
// the same arg-cap signature (Cap::all() from process.env), so the
// inline-analysis cache reuses the cached return shape across the two
// calls.  Origin identity MUST be re-attributed per call site — a
// naive cache would make the second call's return taint carry whichever
// source the cache was populated with first.
const child_process = require('child_process');
const fs = require('fs');

function passthrough(x) {
    return x;
}

// Call site 1: source on line 17.
const sourceA = process.env.USER_INPUT;
const valA = passthrough(sourceA);
child_process.exec(valA);

// Call site 2: source on line 22 — distinct from call site 1.
const sourceB = process.env.OTHER_INPUT;
const valB = passthrough(sourceB);
fs.writeFileSync(valB, 'x');
