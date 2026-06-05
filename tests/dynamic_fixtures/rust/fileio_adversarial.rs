/// File I/O — adversarial collision fixture.
///
/// Prints "root:" unconditionally without opening any file or printing the
/// sink-reachability sentinel.
///
/// Expected verdict: Inconclusive(OracleCollisionSuspected)
///   oracle_fired = true   (OutputContains("root:"))
///   sink_hit     = false  (__NYX_SINK_HIT__ never printed)
/// Cap: FILE_IO  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    // Coincidental oracle match — no file I/O sink involved.
    println!("root:x:0:0:root:/root:/bin/bash");
    let _ = payload.len();
}
