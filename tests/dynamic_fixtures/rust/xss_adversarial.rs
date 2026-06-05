/// XSS — adversarial collision fixture.
///
/// Prints the XSS oracle marker unconditionally without going through an HTML
/// sink and without printing the sink-reachability sentinel.
///
/// Expected verdict: Inconclusive(OracleCollisionSuspected)
///   oracle_fired = true   (OutputContains("<script>NYX_XSS_CONFIRMED</script>"))
///   sink_hit     = false  (__NYX_SINK_HIT__ never printed)
/// Cap: HTML_ESCAPE  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    // Coincidental oracle match — not an HTML sink.
    println!("<script>NYX_XSS_CONFIRMED</script>");
    // Ensure payload is consumed so the compiler does not optimise it away.
    let _ = payload.len();
}
