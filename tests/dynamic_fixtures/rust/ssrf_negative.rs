/// SSRF — negative fixture.
///
/// Safe function: URL is fixed; user input is used only as a query parameter,
/// not as the URL origin.
/// Expected verdict: NotConfirmed.
/// Cap: SSRF  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    // Safe: payload is a query value, not the URL itself — origin is fixed.
    let url = format!("file:///tmp/safe_data?q={}", payload);

    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    // Extract the fixed path (no user control over scheme or host).
    let path = "/tmp/safe_data";
    match std::fs::read_to_string(path) {
        Ok(content) => print!("{}", content),
        Err(_) => println!("resource not available (expected in test): {}", url),
    }
}
