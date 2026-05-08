// Phase 14 fixture (Rust negative) — `format!("https://api.example.com/{}", path)`
// produces a StringFact whose prefix is the literal scheme/host, so
// `is_string_safe_for_ssrf` honours the lock and suppresses the SSRF
// sink at `reqwest::get` even though the path component is
// attacker-controlled.
use std::collections::HashMap;

async fn proxy(headers: &HashMap<String, String>) -> reqwest::Result<String> {
    let path = headers.get("X-Path").cloned().unwrap_or_default();
    let url = format!("https://api.example.com/{}", path);
    let resp = reqwest::get(&url).await?;
    resp.text().await
}
