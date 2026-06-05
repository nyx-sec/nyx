// SQL injection — adversarial collision fixture.
// Prints NYX_SQL_CONFIRMED unconditionally without reaching a SQL sink
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
//   oracle_fired = true, sink_hit = false
// Entry: login(username)  Cap: SQL_QUERY

function login(username) {
    // Coincidental oracle match — not a SQL sink.
    process.stdout.write('NYX_SQL_CONFIRMED\n');
    void username.length;
}

module.exports = { login };
