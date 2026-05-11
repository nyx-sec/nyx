// Phase 14 fixture (Rust search-params positive) — attacker-controlled
// URL passed to `Client::get(url)` chained with `.query(&[("k", v)])`.
// The `Client::new.get` matcher catches the chained-construction shape
// after CFG receiver collapse; the SSRF sink fires at the verb call
// because the URL is fully attacker-controlled.
use std::collections::HashMap;

async fn proxy(headers: &HashMap<String, String>) -> reqwest::Result<String> {
    let target = headers.get("X-Target").cloned().unwrap_or_default();
    let client = reqwest::Client::new();
    let resp = client.get(&target).query(&[("q", "ok")]).send().await?;
    resp.text().await
}
