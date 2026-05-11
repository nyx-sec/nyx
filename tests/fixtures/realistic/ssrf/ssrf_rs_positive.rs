// Phase 14 fixture (Rust positive) — attacker-controlled URL flows
// directly into `reqwest::get`.  The `headers.get` Source matcher
// taints the `target` value, which reaches the `reqwest::get` SSRF
// flat sink at the call site.
use std::collections::HashMap;

async fn proxy(headers: &HashMap<String, String>) -> reqwest::Result<String> {
    let target = headers.get("X-Target").cloned().unwrap_or_default();
    let resp = reqwest::get(&target).await?;
    resp.text().await
}
