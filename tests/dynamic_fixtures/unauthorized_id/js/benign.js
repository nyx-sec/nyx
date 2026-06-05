// Phase 11 (Track J.9) — JavaScript UNAUTHORIZED_ID benign control fixture.
const CALLER_ID = "alice";
const STORE = { alice: "alice@x", bob: "bob@x" };

function run(ownerId) {
    if (ownerId !== CALLER_ID) return null;
    return STORE[ownerId];
}

module.exports = { run };
