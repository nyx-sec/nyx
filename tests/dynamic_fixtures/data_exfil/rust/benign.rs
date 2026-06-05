// Phase 11 (Track J.9) — Rust DATA_EXFIL benign control fixture.
const ALLOWLIST: &[&str] = &["127.0.0.1", "localhost"];

pub fn run(host: &str) {
    if !ALLOWLIST.contains(&host) {
        return;
    }
    let secret = "alice-creds";
    let url = format!("http://{host}/exfil?token={secret}");
    let _ = reqwest::blocking::get(&url);
}
