/// SSRF — second positive fixture.
///
/// Variant: user-controlled URL stored in a struct field before being fetched,
/// exercising a different taint path than ssrf_positive.rs.
/// Expected verdict: Confirmed (payload "file:///etc/passwd" reaches the file
/// reader via the stored URL field).
/// Cap: SSRF  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    let req = Request { url: payload.to_owned() };

    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    let result = req.execute();
    print!("{}", result);
}

struct Request {
    url: String,
}

impl Request {
    fn execute(&self) -> String {
        // Vulnerable: self.url derived from user input — SSRF.
        if let Some(path) = self.url.strip_prefix("file://") {
            std::fs::read_to_string(path)
                .unwrap_or_else(|e| format!("fetch error: {}", e))
        } else {
            format!("SSRF: would connect to {}", self.url)
        }
    }
}
