// Rust negative — `format!(URL_FMT, path)` where URL_FMT is a top-level
// `const &str` declaration. The const-bridge in `cfg::prefix_of_expression`
// resolves URL_FMT to its literal value at AST time, so the resulting
// StringFact carries the locked `https://api.example.com/` prefix and
// `is_string_safe_for_ssrf` suppresses the SSRF sink at `reqwest::get`.
use std::collections::HashMap;

const URL_FMT: &str = "https://api.example.com/users/{}";

async fn proxy(headers: &HashMap<String, String>) -> reqwest::Result<String> {
    let path = headers.get("X-Path").cloned().unwrap_or_default();
    let url = format!(URL_FMT, path);
    let resp = reqwest::get(&url).await?;
    resp.text().await
}
