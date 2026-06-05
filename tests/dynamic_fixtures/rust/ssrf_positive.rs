/// SSRF — positive fixture.
///
/// Vulnerable function: fetches a user-controlled URL. Implements a minimal
/// file:// scheme reader so the test requires no network and no async runtime.
///
/// Expected verdict: Confirmed (payload "file:///etc/passwd" causes "daemon:"
/// to appear in stdout via the file:// scheme handler).
/// Cap: SSRF  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    // Vulnerable: user controls the URL — SSRF via file:// scheme reaches local files.
    let result = fetch_url(payload);
    print!("{}", result);
}

fn fetch_url(url: &str) -> String {
    if let Some(path) = url.strip_prefix("file://") {
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| format!("fetch error: {}", e))
    } else {
        // For non-file schemes, report the target (demonstrating SSRF intent).
        format!("SSRF: would connect to {}", url)
    }
}
