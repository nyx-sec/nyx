/// File I/O — positive fixture.
///
/// Vulnerable function: reads a file at a user-controlled path.
/// Expected verdict: Confirmed (path-traversal payload "../../../../etc/passwd"
/// causes "root:" to appear in stdout).
/// Cap: FILE_IO  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    // Vulnerable: user controls the file path — path traversal possible.
    match std::fs::read_to_string(payload) {
        Ok(contents) => print!("{}", contents),
        Err(e) => eprintln!("Error reading {}: {}", payload, e),
    }
}
