// Phase 11 (Track J.9) — JavaScript UNAUTHORIZED_ID vuln fixture.
const CALLER_ID = "alice";
const STORE = { alice: "alice@x", bob: "bob@x" };

function run(ownerId) {
    return STORE[ownerId];
}

module.exports = { run };
