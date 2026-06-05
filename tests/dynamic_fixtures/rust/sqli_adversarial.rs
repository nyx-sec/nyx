/// SQL injection — adversarial collision fixture.
///
/// Prints "NYX_SQL_CONFIRMED" unconditionally without going through a SQL sink
/// and without printing the sink-reachability sentinel.
///
/// Expected verdict: Inconclusive(OracleCollisionSuspected)
///   oracle_fired = true   (OutputContains("NYX_SQL_CONFIRMED"))
///   sink_hit     = false  (__NYX_SINK_HIT__ never printed)
/// Cap: SQL_QUERY  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    // Coincidental oracle match — not a SQL sink.
    println!("NYX_SQL_CONFIRMED");
    // Ensure payload is consumed so the compiler does not optimise it away.
    let _ = payload.len();
}
