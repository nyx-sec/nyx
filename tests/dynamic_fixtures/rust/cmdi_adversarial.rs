/// Command injection — adversarial collision fixture.
///
/// Prints "NYX_PWN_791_CMDI" unconditionally without going through a shell sink.
///
/// Expected verdict: Inconclusive(OracleCollisionSuspected)
///   oracle_fired = true   (OutputContains("NYX_PWN_791_CMDI"))
///   sink_hit     = false  (__NYX_SINK_HIT__ never printed)
/// Cap: CODE_EXEC  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    // Coincidental oracle match — not a command execution sink.
    println!("NYX_PWN_791_CMDI");
    let _ = payload.len();
}
