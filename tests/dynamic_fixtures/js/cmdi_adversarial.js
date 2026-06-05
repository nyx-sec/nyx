// Command injection — adversarial collision fixture.
// Prints NYX_PWN_791_CMDI unconditionally without reaching a command sink
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: runPing(host)  Cap: CODE_EXEC

function runPing(host) {
    // Coincidental oracle match — not a shell sink.
    process.stdout.write('NYX_PWN_791_CMDI\n');
    void host.length;
}

module.exports = { runPing };
