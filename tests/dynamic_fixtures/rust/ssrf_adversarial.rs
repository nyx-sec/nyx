/// SSRF — adversarial collision fixture.
///
/// Prints "daemon:" unconditionally without making any network or file request,
/// and without printing the sink-reachability sentinel.
///
/// Expected verdict: Inconclusive(OracleCollisionSuspected)
///   oracle_fired = true   (OutputContains("daemon:"))
///   sink_hit     = false  (__NYX_SINK_HIT__ never printed)
/// Cap: SSRF  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    // Coincidental oracle match — no URL fetch or network sink involved.
    println!("daemon:*:1:1:System Services:/var/root:/usr/bin/false");
    let _ = payload.len();
}
